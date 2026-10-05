# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The OAuth2 client-credentials ``auth_style`` default and its record agree (vault BACKLOG #2206).

The default stayed ``"basic"`` by decision, and the reasons are written in two places: the
``with_oauth2_client_credentials`` docstring and ``docs/CONNECTIONS.md``. A record of a default goes
stale the day the default moves, so this pins the three code sites to the two records. Changing the
default without rewriting the record turns it red.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from messagefoundry import Rest
from messagefoundry.transports.http_auth import (
    OAuth2ClientCredentialsProvider,
    oauth2_cc_provider_from_settings,
    with_oauth2_client_credentials,
)

_DOC = Path(__file__).resolve().parents[1] / "docs" / "CONNECTIONS.md"
_TOKEN_URL = "https://auth.example.invalid/token"


def _default(fn: object, name: str = "auth_style") -> object:
    return inspect.signature(fn).parameters[name].default  # type: ignore[arg-type]


def test_the_three_code_sites_default_to_basic() -> None:
    assert _default(with_oauth2_client_credentials) == "basic"
    assert _default(OAuth2ClientCredentialsProvider.__init__) == "basic"
    # The settings reader has its own fallback, for settings that did not come through the composer.
    provider = oauth2_cc_provider_from_settings(
        {
            "oauth2_token_url": _TOKEN_URL,
            "oauth2_client_id": "cid",
            "oauth2_client_secret": "synthetic-secret",
        }
    )
    assert provider is not None and provider.auth_style == "basic"


def test_the_composer_writes_the_default_into_the_settings() -> None:
    spec = with_oauth2_client_credentials(
        Rest(url="https://api.example.invalid/x"),
        token_url=_TOKEN_URL,
        client_id="cid",
        client_secret="synthetic-secret",
    )
    assert spec.settings["oauth2_auth_style"] == "basic"


def test_the_docstring_records_the_decision_and_names_the_stronger_option() -> None:
    doc = inspect.getdoc(with_oauth2_client_credentials) or ""
    assert 'Why ``auth_style`` defaults to ``"basic"``' in doc
    assert "RFC 6749 section 2.3.1" in doc
    assert "with_smart_backend" in doc
    # The record must not read as a claim about the header's encoding.
    assert "not a claim that the header" in doc


def test_the_connections_doc_records_the_same_default() -> None:
    text = _DOC.read_text(encoding="utf-8")
    assert '`auth_style` defaults to `"basic"`' in text
    assert "vault BACKLOG #2206" in text
