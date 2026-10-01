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
    assert "no outbound url carries a credential-like query parameter" in r.detail
