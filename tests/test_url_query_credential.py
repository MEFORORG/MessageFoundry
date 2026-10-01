# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A credential in an outbound ``url``'s query string is a RECORDED loosening (ASVS 14.2.1).

The vault re-read of 2026-10-01 found it accepted with no line anywhere: ``refuse_url_credentials``
covers the userinfo and never the query. It is WARNED and reported rather than refused; the reason is
on ``pipeline.wiring_runner.warn_url_query_credentials``. Every positive arm has a benign-parameter
control, so a test is not green because the detector names every parameter.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    EnvRef,
    Registry,
    build_outbound_connection,
    query_credential_hops,
)
from messagefoundry.pipeline.wiring_runner import check_egress_allowed
from messagefoundry.secretscrub import credential_query_params

_MARK = "carries a credential in its query string"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://p.example.invalid/x?key=AAA&fmt=json", ["key"]),
        ("https://p.example.invalid/x?subscription-key=AAA", ["subscription-key"]),
        ("https://p.example.invalid/blob?sv=1&sig=AAA&se=2", ["sig"]),
        (
            "https://p.example.invalid/x?X-Amz-Signature=A&X-Amz-Credential=B",
            ["X-Amz-Credential", "X-Amz-Signature"],
        ),
        ("https://p.example.invalid/x?access_token=AAA", ["access_token"]),
        (
            "https://p.example.invalid/x?api_key=A&client_secret=B&password=C",
            ["api_key", "client_secret", "password"],
        ),
    ],
)
def test_detector_names_credential_parameters(url: str, expected: list[str]) -> None:
    assert credential_query_params(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        # Benign controls: substrings of a credential word that are not the word.
        "https://p.example.invalid/x?format=json&keyword=lab&monkey=1&bypass=2&passage=3",
        "https://p.example.invalid/x?code=404&state=RUNNING",  # OIDC words, ordinary here
        "https://p.example.invalid/x",
        "not a url at all",
    ],
)
def test_detector_leaves_benign_parameters_alone(url: str) -> None:
    assert credential_query_params(url) == []


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        # camelCase tails, the common partner spellings the first cut missed.
        (
            "https://p.example.invalid/x?accessToken=a&clientSecret=b",
            ["accessToken", "clientSecret"],
        ),
        ("https://p.example.invalid/x?apiKey=a&authToken=b", ["apiKey", "authToken"]),
        # Acronym-prefixed Title-case segments (review round 2).
        ("https://p.example.invalid/x?SASToken=a&HMACSignature=b", ["HMACSignature", "SASToken"]),
        # Control: a lower-case run is not a camelCase boundary, and all-capitals is not split.
        ("https://p.example.invalid/x?turkey=a&MONKEY=b&hotkeys=c", []),
        # Control: pagination cursors, sort keys and public keys end in a credential word only.
        ("https://p.example.invalid/x?pageToken=a&next_page_token=b&sortKey=c&publicKey=d", []),
    ],
)
def test_detector_reads_camel_case_tails(url: str, expected: list[str]) -> None:
    assert credential_query_params(url) == expected


def test_detector_escapes_a_control_character_in_a_decoded_name() -> None:
    """``parse_qsl`` decodes ``%0A``; the name reaches a log line, so it must not carry a raw newline."""
    [name] = credential_query_params("https://p.example.invalid/x?x%0Afake_token=1")
    assert "\n" not in name and name.isprintable()
    assert "fake_token" in name  # still named, escaped rather than dropped


def test_a_decoded_name_cannot_forge_a_second_entry() -> None:
    """A printable name can still carry ``); `` that reads as the end of one ``check`` entry."""
    [name] = credential_query_params("https://p.example.invalid/x?a%29%3B%20OB_EVIL%20%28api_key=1")
    assert name.startswith("'") and name.endswith("'")  # quoted by repr, so it reads as one name


def test_redacted_settings_masks_an_env_default_url_and_other_url_keys() -> None:
    """The env() DEFAULT and a URL-suffixed key other than ``url`` reach /metadata too."""
    from messagefoundry.config.wiring import env, redacted_settings

    shown = redacted_settings(
        {
            "url": env("MEFOR_URL", default="https://u:pw@p.example.invalid/x?key=SYNTHETIC-7"),
            "smart_token_url": "https://t.example.invalid/token?client_secret=SYNTHETIC-8",
        }
    )
    assert shown["url"]["default"] == "https://u:***@p.example.invalid/x?key=***"
    assert shown["smart_token_url"] == "https://t.example.invalid/token?client_secret=***"


def test_userinfo_mask_ignores_an_at_sign_in_the_query() -> None:
    """``_mask_url_userinfo`` split at the LAST ``@`` in the URL, so an ``@`` in a query was read as
    the end of a userinfo and the view showed the wrong host."""
    from messagefoundry.config.wiring import redacted_settings

    url = "https://h.example.invalid:8443/x?email=a@b.example.invalid&key=SYNTHETIC-9"
    assert (
        redacted_settings({"url": url})["url"]
        == "https://h.example.invalid:8443/x?email=a@b.example.invalid&key=***"
    )


def test_mask_and_detector_agree_on_where_the_query_is() -> None:
    """A ``?`` after the ``#`` is fragment, not query, for both."""
    from messagefoundry.secretscrub import mask_credential_query

    url = "https://p.example.invalid/x#frag?key=S"
    assert credential_query_params(url) == []
    assert mask_credential_query(url) == url


def test_redacted_settings_masks_the_query_value_and_keeps_the_rest() -> None:
    """``GET /metadata`` and ``graph --json`` serve settings through ``redacted_settings``. Before the
    review fix it masked only the userinfo, so the key the WARNING named was served verbatim."""
    from messagefoundry.config.wiring import redacted_settings

    url = "https://u:pw@p.example.invalid/x?key=SYNTHETIC-5&fmt=json#frag"
    shown = redacted_settings({"url": url})["url"]
    assert shown == "https://u:***@p.example.invalid/x?key=***&fmt=json#frag"
    # Control: a benign query is untouched.
    benign = "https://p.example.invalid/x?fmt=json&keyword=lab"
    assert redacted_settings({"url": benign})["url"] == benign


def test_detector_returns_names_never_values() -> None:
    names = credential_query_params("https://p.example.invalid/x?token=SYNTHETIC-SECRET-1")
    assert names == ["token"]
    assert not any("SYNTHETIC" in n for n in names)


# --- the construction WARNING ------------------------------------------------------------------


def _rest(url: str) -> Destination:
    return Destination(name="OB_REST", type=ConnectorType.REST, settings={"url": url})


def test_build_warns_naming_the_connection_and_parameter_never_the_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        check_egress_allowed(
            _rest("https://p.example.invalid/x?key=SYNTHETIC-SECRET-2&fmt=json"), EgressSettings()
        )
    [line] = [r.getMessage() for r in caplog.records if _MARK in r.getMessage()]
    assert "'OB_REST'" in line and "(parameter(s) key)" in line
    assert "SYNTHETIC-SECRET-2" not in line and "p.example.invalid" not in line


def test_build_with_a_benign_query_is_silent(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        check_egress_allowed(
            _rest("https://p.example.invalid/x?fmt=json&keyword=lab"), EgressSettings()
        )
    assert not [r for r in caplog.records if _MARK in r.getMessage()]


def test_build_is_not_refused_under_an_allowlist(caplog: pytest.LogCaptureFixture) -> None:
    """Warn, not refuse: the allow-listed branch, which does refuse userinfo, still lets it through."""
    egress = EgressSettings(allowed_http=["p.example.invalid"])
    with caplog.at_level(logging.WARNING):
        check_egress_allowed(_rest("https://p.example.invalid/x?sig=SYNTHETIC"), egress)
    assert [r for r in caplog.records if _MARK in r.getMessage()]


# --- the single reader, `check` and the registry -----------------------------------------------


def _registry() -> Registry:
    reg = Registry()
    for name, url in (
        ("OB_KEYED", "https://p.example.invalid/x?key=SYNTHETIC-3"),
        ("OB_PLAIN", "https://p.example.invalid/x?fmt=json"),
    ):
        reg.add_outbound(
            build_outbound_connection(
                name, ConnectionSpec(type=ConnectorType.REST, settings={"url": url})
            )
        )
    reg.add_outbound(
        build_outbound_connection(
            "OB_ENV",
            ConnectionSpec(type=ConnectorType.REST, settings={"url": EnvRef("MEFOR_ENV_URL")}),
        )
    )
    return reg


def test_reader_lists_only_the_credentialed_url_and_no_value() -> None:
    assert query_credential_hops(_registry()) == [("OB_KEYED", "key")]


def test_reader_and_build_cover_a_fhir_lookup(caplog: pytest.LogCaptureFixture) -> None:
    """A FhirLookup dials its ``url`` too, through its own egress check, so both surfaces reach it."""
    from messagefoundry.config.wiring import FhirLookupSpec
    from messagefoundry.pipeline.wiring_runner import check_fhir_lookup_allowed

    reg = _registry()
    url = "https://fhir.example.invalid/R4?api_key=SYNTHETIC-6"
    reg.add_fhir_lookup(FhirLookupSpec(name="LK", settings={"url": url}))
    assert ("fhir_lookup:LK", "api_key") in query_credential_hops(reg)
    with caplog.at_level(logging.WARNING):
        check_fhir_lookup_allowed("LK", {"url": url}, EgressSettings())
    [line] = [r.getMessage() for r in caplog.records if _MARK in r.getMessage()]
    assert "FhirLookup 'LK'" in line and "SYNTHETIC" not in line


_CONFIG = """
from messagefoundry import MLLP, Rest, Send, handler, inbound, outbound, router

inbound("IB", MLLP(port=15098), router="r")
outbound("OB_KEYED", Rest(url="https://p.example.invalid/x?sig=SYNTHETIC-4"))
outbound("OB_PLAIN", Rest(url="https://p.example.invalid/x?fmt=json"))


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    return Send("OB_KEYED", msg)
"""

_TOML = """
[store]
backend = "sqlite"

[ai]
environment = "dev"

[security]
block_unlisted_outbound = false
allow_unencrypted_phi = true
allow_unencrypted_phi_under_strict_enforcement = true
"""


def _write(tmp_path: Path, module: str) -> Path:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text(module, encoding="utf-8")
    (tmp_path / "messagefoundry.toml").write_text(_TOML, encoding="utf-8")
    return cfg


def test_check_names_the_connection_and_parameter(tmp_path: Path) -> None:
    from messagefoundry.checks import run_checks

    report = run_checks(_write(tmp_path, _CONFIG), run_lint=False)
    r = next(x for x in report.results if x.name == "url-query-credential")
    assert r.ok and not r.required and not r.skipped
    assert "OB_KEYED (sig)" in r.detail
    assert "OB_PLAIN" not in r.detail and "SYNTHETIC" not in r.detail


def test_check_says_none_on_a_clean_graph(tmp_path: Path) -> None:
    from messagefoundry.checks import run_checks

    clean = _CONFIG.replace("?sig=SYNTHETIC-4", "?fmt=xml")
    report = run_checks(_write(tmp_path, clean), run_lint=False)
    r = next(x for x in report.results if x.name == "url-query-credential")
    assert "no outbound or FhirLookup url carries a credential-like query parameter" in r.detail
