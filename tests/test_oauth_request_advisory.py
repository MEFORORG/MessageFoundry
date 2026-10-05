# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The OAuth request advisory: a wildcard ``oauth2_scope``, and an audience that is not its endpoint
(vault BACKLOG #2334, ASVS 10.2.3).

``oauth2_scope``, ``oauth2_audience`` and ``smart_audience`` reached the wire through one ``str(...)``
conversion and no rule read them. On a first deployment with a broad scope or a wrong audience,
nothing would warn.

Each setting has a firing case and a control beside it, because the silences carry the same weight as
the findings. An advisory that fires on a valid configuration teaches operators to ignore it. The
third thing under test is the stated limit: the reader compares literal values only, so a setting it
could not compare must be NAMED, never passed over as clean.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry import redaction
from messagefoundry.checks import CheckResult, run_checks
from messagefoundry.config.wiring import (
    OAuthRequestAdvisories,
    load_config,
    oauth_request_advisories,
)

_HEADER = """
from messagefoundry import FHIR, FhirLookup, Rest, env, outbound
from messagefoundry.transports.http_auth import with_oauth2_client_credentials
from messagefoundry.transports.smart import with_smart_backend

_KEY = "env-placeholder-signing-material"
_TOKEN = "https://auth.example.invalid/oauth2/token"
_API = "https://api.example.invalid/claims"


def _oauth(name, *, url=_API, **kw):
    kw.setdefault("token_url", _TOKEN)
    outbound(name, with_oauth2_client_credentials(
        Rest(url=url), client_id="cid", client_secret=env("partner_secret"), **kw
    ))


def _smart(name, *, token_url=_TOKEN, **kw):
    outbound(name, with_smart_backend(
        FHIR(url="https://fhir.example.invalid/fhir", interaction="create"),
        token_url=token_url, client_id="cid", private_key=_KEY, **kw
    ))
"""


def _config(tmp_path: Path, body: str) -> Path:
    cfg = tmp_path / "config"
    cfg.mkdir(parents=True)
    (cfg / "feed.py").write_text(_HEADER + body, encoding="utf-8")
    return cfg


def _read(tmp_path: Path, body: str) -> OAuthRequestAdvisories:
    return oauth_request_advisories(load_config(_config(tmp_path, body)))


def _named(pairs: list[tuple[str, str]]) -> list[str]:
    return [name for name, _ in pairs]


# --- oauth2_scope -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("scope", "echoed"),
    [
        ("*", "*"),
        ("claims.*", "claims.*"),
        ("*/*", "*/*"),
        ("read:*", "read:*"),
        ("system/*.rs", "system/*.rs"),
        # Only the wildcard token is echoed, never the named scope beside it.
        ("claims.write claims.*", "claims.*"),
        # A prefix wildcard, and a comma-joined list, which is one token on the wire.
        ("claims.read s3:Get*", "s3:Get*"),
        ("claims.*,claims.read", "claims.*,claims.read"),
    ],
)
def test_a_wildcard_oauth2_scope_is_named(tmp_path: Path, scope: str, echoed: str) -> None:
    read = _read(tmp_path, f'_oauth("OB_WILD", scope={scope!r})\n')
    assert read.findings == [("OB_WILD", f"oauth2_scope requests a wildcard: {echoed}")]
    assert read.not_compared == []


@pytest.mark.parametrize(
    "scope",
    [
        "claims.write",  # THE CONTROL: the shipped worked example
        "claims.read claims.write eligibility.read remittance.read prior-auth.submit",
        "https://api.example.invalid/.default",
        None,
    ],
)
def test_a_named_oauth2_scope_is_never_graded(tmp_path: Path, scope: str | None) -> None:
    read = _read(tmp_path, f'_oauth("OB_NAMED", scope={scope!r})\n')
    assert read == OAuthRequestAdvisories(findings=[], not_compared=[])


def test_a_wildcard_token_that_would_not_print_is_described_not_echoed(tmp_path: Path) -> None:
    # The token is bound for a terminal. An escape byte in it must not reach the check line.
    read = _read(tmp_path, '_oauth("OB_ESC", scope="claims.read a\x1b[31m* claims.*")\n')
    assert read.findings == [
        ("OB_ESC", "oauth2_scope requests a wildcard: (a token not shown) claims.*")
    ]


def test_a_wildcard_scope_is_quiet_when_the_provider_is_off(tmp_path: Path) -> None:
    read = _read(tmp_path, '_oauth("OB_OFF", scope="claims.*", enabled=False)\n')
    assert read == OAuthRequestAdvisories(findings=[], not_compared=[])


def test_an_env_scope_is_named_as_not_compared(tmp_path: Path) -> None:
    read = _read(tmp_path, '_oauth("OB_ENV", scope=env("partner_scope"))\n')
    assert read.findings == []
    assert read.not_compared == [("OB_ENV", "oauth2_scope is an env() reference")]


# --- smart_audience -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("audience", "how"),
    [
        (
            "https://other.example.invalid/oauth2/token",
            "it names https://other.example.invalid:443 and the token endpoint is "
            "https://auth.example.invalid:443",
        ),
        (
            "https://auth.example.invalid/oauth2/other",
            "it is on the same origin, https://auth.example.invalid:443, and is a different URL",
        ),
        ("urn:example:authorization-server", "it is not an http(s) URL that check can read"),
        # Sent as written, so a server that compares the audience as text would refuse these two.
        (
            "https://auth.example.invalid/oauth2/token/",
            "it differs only by letter case or a trailing slash, and it is sent as written",
        ),
        (
            "HTTPS://Auth.Example.Invalid/oauth2/token",
            "it differs only by letter case or a trailing slash, and it is sent as written",
        ),
        # The default port written out is the same origin and a different string.
        (
            "https://auth.example.invalid:443/oauth2/token",
            "it is on the same origin, https://auth.example.invalid:443, and is a different URL",
        ),
    ],
)
def test_a_smart_audience_that_is_not_the_token_endpoint_is_named(
    tmp_path: Path, audience: str, how: str
) -> None:
    read = _read(tmp_path, f'_smart("OB_AUD", audience={audience!r})\n')
    assert read.findings == [("OB_AUD", f"smart_audience is not the token URL: {how}")]


@pytest.mark.parametrize(
    "audience",
    [
        None,  # THE CONTROL: unset, so the provider sends the token URL
        "",  # falsy, which the provider also reads as unset
        "https://auth.example.invalid/oauth2/token",
    ],
)
def test_a_smart_audience_equal_to_the_token_endpoint_is_quiet(
    tmp_path: Path, audience: str | None
) -> None:
    read = _read(tmp_path, f'_smart("OB_AUD", audience={audience!r})\n')
    assert read == OAuthRequestAdvisories(findings=[], not_compared=[])


def test_a_smart_audience_is_quiet_when_the_provider_is_off(tmp_path: Path) -> None:
    body = '_smart("OB_OFF", audience="https://other.example.invalid/token", enabled=False)\n'
    assert _read(tmp_path, body) == OAuthRequestAdvisories(findings=[], not_compared=[])


def test_a_smart_audience_on_a_lookup_is_read_too(tmp_path: Path) -> None:
    body = (
        # A graph must declare a connection to load, and a lookup is not one.
        '_smart("OB_PLAIN")\n'
        "with_smart_backend(\n"
        '    FhirLookup("lk", url="https://fhir.example.invalid/fhir"), token_url=_TOKEN,\n'
        '    client_id="cid", private_key=_KEY, audience="https://other.example.invalid/token",\n'
        ")\n"
    )
    assert _named(_read(tmp_path, body).findings) == ["fhir_lookup:lk"]


def test_an_unresolved_smart_value_is_named_as_not_compared(tmp_path: Path) -> None:
    body = (
        '_smart("OB_AUD_ENV", audience=env("epic_aud"))\n'
        '_smart("OB_URL_ENV", token_url=env("epic_token_url"), audience="https://a.example.invalid/t")\n'
        # No audience at all: the provider sends the token URL, so there is nothing to compare.
        '_smart("OB_NO_AUD", token_url=env("epic_token_url"))\n'
    )
    read = _read(tmp_path, body)
    assert read.findings == []
    assert read.not_compared == [
        ("OB_AUD_ENV", "smart_audience is an env() reference"),
        ("OB_URL_ENV", "smart_token_url is an env() reference"),
    ]


# --- oauth2_audience ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("audience", "named"),
    [
        ("https://other.example.invalid/claims", "https://other.example.invalid:443"),
        ("https://api.example.invalid:8443/claims", "https://api.example.invalid:8443"),
        ("http://api.example.invalid/claims", "http://api.example.invalid:80"),
    ],
)
def test_an_oauth2_audience_on_another_origin_is_named(
    tmp_path: Path, audience: str, named: str
) -> None:
    read = _read(tmp_path, f'_oauth("OB_AUD", audience={audience!r})\n')
    assert read.findings == [
        (
            "OB_AUD",
            f"oauth2_audience names {named} and the connection calls "
            "https://api.example.invalid:443",
        )
    ]


@pytest.mark.parametrize(
    "audience",
    [
        "https://api.example.invalid/",  # THE CONTROL: the same origin, another path
        "https://API.example.invalid:443/v2",  # the default port written out, and host case
        "https://api.example.invalid./claims",  # a trailing dot on the host
        "partner-claims-api",  # an opaque API identifier, which many servers use
        "api://partner-claims",
        "urn:example:claims",
        None,
    ],
)
def test_an_oauth2_audience_on_the_same_origin_or_opaque_is_quiet(
    tmp_path: Path, audience: str | None
) -> None:
    read = _read(tmp_path, f'_oauth("OB_AUD", audience={audience!r})\n')
    assert read == OAuthRequestAdvisories(findings=[], not_compared=[])


def test_an_oauth2_audience_is_quiet_when_the_provider_is_off(tmp_path: Path) -> None:
    body = '_oauth("OB_OFF", audience="https://other.example.invalid/x", enabled=False)\n'
    assert _read(tmp_path, body) == OAuthRequestAdvisories(findings=[], not_compared=[])


def test_an_unresolved_oauth2_value_is_named_as_not_compared(tmp_path: Path) -> None:
    body = (
        '_oauth("OB_AUD_ENV", audience=env("partner_aud"))\n'
        '_oauth("OB_URL_ENV", url=env("partner_url"), audience="https://api.example.invalid/")\n'
        # An opaque identifier is never compared with the url, so an env() url hides nothing here.
        '_oauth("OB_OPAQUE", url=env("partner_url"), audience="partner-claims-api")\n'
    )
    read = _read(tmp_path, body)
    assert read.findings == []
    assert read.not_compared == [
        ("OB_AUD_ENV", "oauth2_audience is an env() reference"),
        ("OB_URL_ENV", "url is an env() reference"),
    ]


def test_a_finding_never_copies_a_path_a_query_or_a_userinfo(tmp_path: Path) -> None:
    # A token URL or an audience can carry a tenant path or a query value. The finding is built from
    # parsed parts, scheme, host and port, so neither can reach the check output.
    body = (
        '_smart("OB_S", token_url="https://auth.example.invalid/t/tenant-path?k=query-value",\n'
        '       audience="https://user-part@other.example.invalid/aud-path?q=aud-query")\n'
        '_oauth("OB_O", url="https://api.example.invalid/hook/url-path?k=url-query",\n'
        '       audience="https://other.example.invalid/aud2-path?q=aud2-query")\n'
    )
    text = repr(_read(tmp_path, body).findings)
    assert "OB_S" in text and "OB_O" in text
    for leaked in ("tenant-path", "query-value", "user-part", "aud-path", "aud-query", "url-path",
                   "url-query", "aud2-path", "aud2-query"):  # fmt: skip
        assert leaked not in text


def test_a_url_shaped_credential_never_reaches_a_finding(tmp_path: Path) -> None:
    # A credential holding an unencoded `/` makes a URL parser read its head as the host. The origin
    # is built on `_split_address`, which refuses that shape, so the head is never printed.
    body = (
        '_smart("OB_S", audience="https://head-part/tail@auth.example.invalid/oauth2/token")\n'
        '_oauth("OB_O", url="https://key-head/tail@api.example.invalid/hook",\n'
        '       audience="https://api.example.invalid/")\n'
    )
    read = _read(tmp_path, body)
    text = repr(read)
    assert "head-part" not in text and "key-head" not in text
    assert read.findings == [
        (
            "OB_S",
            "smart_audience is not the token URL: it is not an http(s) URL that check can read",
        )
    ]
    assert read.not_compared == [("OB_O", "url is not an http(s) URL that check can read")]


def test_a_setting_that_is_not_a_string_is_named_as_not_compared(tmp_path: Path) -> None:
    # The provider sends str() of whatever it is given. A value this reader cannot read as a string
    # must be named, never passed over as clean.
    body = (
        '_oauth("OB_LIST", scope=["claims.*"])\n'
        '_oauth("OB_BAD_PORT", audience="https://api.example.invalid:99999/x")\n'
    )
    read = _read(tmp_path, body)
    assert read.findings == []
    assert read.not_compared == [
        ("OB_BAD_PORT", "oauth2_audience is an http(s) URL that check cannot read"),
        ("OB_LIST", "oauth2_scope is not a string"),
    ]


def test_an_unreadable_token_url_is_not_blamed_on_the_audience(tmp_path: Path) -> None:
    body = (
        '_smart("OB_T", token_url="https://auth.example.invalid:99999/t",\n'
        '       audience="https://other.example.invalid/t")\n'
    )
    assert _read(tmp_path, body).findings == [
        (
            "OB_T",
            "smart_audience is not the token URL: it names https://other.example.invalid:443, and "
            "the token URL is not an http(s) URL that check can read",
        )
    ]


# --- `messagefoundry check` ---------------------------------------------------------------------

_MIXED = (
    '_oauth("OB_WILD", scope="claims.*")\n'
    '_oauth("OB_NAMED", scope="claims.write")\n'
    '_smart("OB_AUD", audience="https://other.example.invalid/token")\n'
    '_oauth("OB_URL_ENV", url=env("partner_url"), audience="https://api.example.invalid/")\n'
)


def _line(cfg: Path) -> CheckResult:
    [r] = [r for r in run_checks(cfg, run_lint=False).results if r.name == "oauth-request"]
    return r


def test_check_names_each_finding_and_what_it_did_not_compare(tmp_path: Path) -> None:
    r = _line(_config(tmp_path, _MIXED))
    assert r.ok and not r.required and not r.skipped and not r.blocking
    assert r.detail.startswith("2 OAuth request setting(s) are worth a second look: ")
    assert "OB_WILD: oauth2_scope requests a wildcard: claims.*" in r.detail
    assert "OB_AUD: smart_audience is not the token URL" in r.detail
    assert "OB_NAMED" not in r.detail
    # The finding can be a correct configuration, and the line has to say so.
    assert "Each can be a correct setup" in r.detail
    assert "may document an audience that is not its endpoint" in r.detail
    # The stated limit: a quiet audience on an env() url is named, never passed over as clean.
    assert "Not compared: 1 setting(s)" in r.detail
    assert "each for the reason beside it" in r.detail
    assert "does not resolve env(): OB_URL_ENV (url is an env() reference)" in r.detail


def test_the_check_line_survives_the_phi_name_heuristic(tmp_path: Path) -> None:
    # The redaction scrubs two adjacent ALL-CAPS or Title-case words as a possible patient name.
    # This line is built through a local variable, which the engine-text scan cannot see, so it is
    # checked here as rendered, with every arm of the text present.
    r = _line(_config(tmp_path, _MIXED))
    assert "Not compared" in r.detail and "worth a second look" in r.detail
    assert redaction._NAME_RUN.findall(r.detail) == []


def test_check_says_none_out_loud_and_still_names_what_it_did_not_compare(tmp_path: Path) -> None:
    r = _line(_config(tmp_path, '_oauth("OB_NAMED", scope="claims.write")\n'))
    assert r.ok and not r.skipped
    assert r.detail == (
        "no oauth2_scope that could be read contains a '*', and no audience that could be "
        "compared differs from its endpoint"
    )
    r = _line(_config(tmp_path / "second", '_oauth("OB_E", audience=env("partner_aud"))\n'))
    assert r.detail.startswith("no oauth2_scope that could be read contains a '*'")
    assert "Not compared: 1 setting(s)" in r.detail and "OB_E" in r.detail


def test_check_skips_rather_than_reporting_clean_on_an_unloadable_config(tmp_path: Path) -> None:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "broken.py").write_text("this is not python(", encoding="utf-8")
    r = _line(cfg)
    assert r.skipped and r.ok and not r.required and "config did not load" in r.detail
