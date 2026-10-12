# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The settings view withholds a credential in seven more shapes (BACKLOG #2721).

``redacted_settings`` is the one scrub behind ``GET /connections/{name}/metadata`` and
``messagefoundry graph --json``. Engine PR 1912's third review left seven shapes open, and a probe
confirmed each one: a whole ``headers`` table with an ``env()`` default, a reference-valued
default, a compound query name, a credential word as a path segment, a name after an encoded
separator, a list-valued URL setting, and a name such as ``no_proxy`` read as a URL. Each test
here pairs the shape with a control that must stay readable, because a view that withheld
everything would pass the shape alone. Every value is synthetic.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

import messagefoundry
from messagefoundry.config.wiring import (
    _is_url_setting,
    env,
    redacted_settings,
)
from messagefoundry.secretscrub import credential_query_params
from tests.test_connection_factory_redaction_domain import (
    FACTORIES,
    _call_with_sentinels,
    _resolve,
)

#: The synthetic value each shape hides. Short and plain, so no other scrub can hide it first.
MARK = "SYNTHMARK7"


def _shown(settings: dict[str, Any]) -> dict[str, Any]:
    """The view, after proving ``json.dumps`` takes it: the API and ``graph --json`` both encode it."""
    view = redacted_settings(settings)
    json.dumps(view)
    return view


# --- shape 1: a whole headers table supplied by env() keeps its default ------------------------


def test_a_headers_table_env_default_is_scrubbed_like_a_literal_table() -> None:
    """Only a headers value that was a dict was walked, so a whole-table reference kept its default.
    ``Rest()`` accepts this shape at run time, though its annotation names a dict only, so it is
    reachable from authored config."""
    headers: Any = env("partner_headers", default={"Authorization": f"Bearer {MARK}"})
    spec = messagefoundry.Rest(url="https://h.example.invalid/x", headers=headers)
    view = _shown(dict(spec.settings))
    assert MARK not in json.dumps(view), view
    assert view["headers"] == {"env": "partner_headers", "default": {"Authorization": "***"}}


def test_the_raw_marker_form_of_a_headers_table_is_scrubbed_too() -> None:
    """The undecoded ``connections.toml`` marker of the same shape."""
    marker = {"env": "partner_headers", "default": {"X-Partner": f"Bearer {MARK}"}}
    view = _shown({"headers": marker})
    assert view["headers"] == {"env": "partner_headers", "default": {"X-Partner": "***"}}


def test_a_headers_table_default_keeps_a_public_header_readable() -> None:
    """The control: the walk applies the header rule, it does not blank the default."""
    view = _shown({"headers": env("h", default={"Accept": "application/fhir+json"})})
    assert view["headers"] == {"env": "h", "default": {"Accept": "application/fhir+json"}}


# --- shape 2: a reference-valued default --------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "inner"),
    [
        ("url", f"https://u:{MARK}@h.example.invalid/x"),
        ("host", MARK),
    ],
)
def test_a_reference_inside_a_default_is_named_by_its_key_only(name: str, inner: str) -> None:
    """``env("a", default=env("b", default=...))`` showed the inner default, and the raw ``EnvRef``
    it left in the view made ``json.dumps`` refuse the whole map. #2519 (refuse the shape at load)
    has not landed, so the view still has to handle it."""
    view = _shown({name: env("a", default=env("b", default=inner))})
    assert view[name] == {"env": "a", "default": {"env": "b"}}


def test_a_raw_marker_inside_a_default_is_named_by_its_key_only() -> None:
    view = _shown({"host": env("a", default={"env": "b", "default": MARK})})
    assert view["host"] == {"env": "a", "default": {"env": "b"}}


def test_a_plain_default_is_still_shown() -> None:
    """The control: one level of default on a non-credential setting is shown, as before."""
    assert _shown({"host": env("a", default="h.example.invalid")})["host"] == {
        "env": "a",
        "default": "h.example.invalid",
    }


# --- shape 3: a credential word inside a compound query name ------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        f"sslpassword={MARK}",
        f"dbpassword={MARK}",
        f"user[password]={MARK}",
        f"x_api_key_v2={MARK}",
        f"fmt=json&clientSecretValue={MARK}",
        f"a=1;tokenvalue={MARK}",
    ],
)
def test_a_compound_query_name_holding_a_credential_word_is_withheld(query: str) -> None:
    url = f"https://h.example.invalid/x?{query}"
    assert _shown({"url": url})["url"] == "https://<redacted>"


@pytest.mark.parametrize(
    "query",
    [
        "keyword=lab",
        "pageToken=abc",
        "page_token[0]=abc",
        "nextToken2=abc",
        "sortKey=name",
        "author=x&session_count=2&design=1",
    ],
)
def test_a_name_with_no_credential_word_or_a_benign_ending_stays_readable(query: str) -> None:
    """The controls. ``key``, ``auth``, ``session`` and ``sig`` are too common inside ordinary
    names for the anywhere rule, and a known non-secret ending such as ``pageToken`` is kept."""
    url = f"https://h.example.invalid/x?{query}"
    assert _shown({"url": url})["url"] == url


def test_the_warning_detector_is_unchanged_by_the_display_rule() -> None:
    """The wider name rule is display only. The detector feeds the egress warning, ``check`` and
    ``query_credential_hops``, and those keep their narrower tail rule."""
    assert credential_query_params(f"https://h.example.invalid/x?sslpassword={MARK}") == []


# --- shape 4: a credential word as a path segment (Manager ruling, batch 255) -----------------


@pytest.mark.parametrize(
    "path",
    [
        f"/token/{MARK}",
        f"/api_key/{MARK}/x",
        f"/v1/tokens/{MARK}",
        f"/key/{MARK}",
        f"/hooks/client-secret/{MARK}",
        f"/x/token%2F{MARK}",  # an escaped "/" splits too
    ],
)
def test_a_credential_word_segment_with_a_segment_after_it_is_withheld(path: str) -> None:
    assert _shown({"url": f"https://h.example.invalid{path}"})["url"] == "https://<redacted>"


@pytest.mark.parametrize(
    "path",
    [
        "/oauth2/token",
        "/oauth2/v2.0/token?scope=x",
        "/token/",
        "/auth/realms/demo/protocol/openid-connect/token",
        "/services/T000/B000/plain",
    ],
)
def test_a_credential_word_as_the_last_segment_stays_readable(path: str) -> None:
    """The ruling's other half: a token endpoint ends in its credential word and names an endpoint,
    so it stays readable. ``auth`` is not a segment word, so a Keycloak path is shown. A bare path
    secret with no credential word before it is still shown: the rule's stated limit."""
    url = f"https://h.example.invalid{path}"
    assert _shown({"url": url})["url"] == url


# --- shape 5: a credential name after an encoded separator -------------------------------------


@pytest.mark.parametrize("escape", ["%26", "%3B", "%3F", "%23", "%3b", "%3f", "%2\t6"])
def test_an_encoded_separator_withholds_the_url(escape: str) -> None:
    """A reader that decodes twice takes the escape as a separator and the text after it as a name.
    Matched in any case, and with tab, CR and LF removed first, as ``urlsplit`` removes them."""
    url = f"https://h.example.invalid/x?a=1{escape}api_key={MARK}"
    assert _shown({"url": url})["url"] == "https://<redacted>"


def test_an_ordinary_escape_stays_readable() -> None:
    url = "https://h.example.invalid/a%20b?q=x%2Cy"
    assert _shown({"url": url})["url"] == url


# --- shape 6: a name that ends in a URL word and holds no URL ---------------------------------


@pytest.mark.parametrize("name", ["no_proxy", "use_proxy", "proxy_no_proxy", "NO_PROXY"])
def test_a_proxy_exclusion_or_flag_is_not_a_url_setting(name: str) -> None:
    assert not _is_url_setting(name)
    assert _shown({name: "a@b.example.invalid,c"})[name] == "a@b.example.invalid,c"


@pytest.mark.parametrize(
    "name",
    ["url", "uri", "proxy", "proxy_url", "http_proxy", "fhir_endpoint", "fallback_urls"],
)
def test_a_url_setting_is_still_one(name: str) -> None:
    assert _is_url_setting(name)


# --- shape 7: a list-valued URL setting -------------------------------------------------------


@pytest.mark.parametrize("name", ["fallback_url", "fallback_urls"])
def test_a_url_inside_a_list_is_withheld(name: str) -> None:
    view = _shown(
        {name: ["https://plain.example.invalid/x", f"https://u:{MARK}@h.example.invalid/x"]}
    )
    assert view[name] == ["https://plain.example.invalid/x", "https://<redacted>"]


def test_a_url_nested_deeper_or_in_a_tuple_is_withheld() -> None:
    view = _shown(
        {
            "mirror_url": (f"https://h.example.invalid/x?api_key={MARK}",),
            "endpoint": {"primary": [f"https://u:{MARK}@h.example.invalid/x"]},
        }
    )
    assert view["mirror_url"] == ("https://<redacted>",)
    assert view["endpoint"] == {"primary": ["https://<redacted>"]}


def test_a_set_renders_as_a_list_and_a_self_holding_list_stops() -> None:
    """``json.dumps`` refuses a set, and a list that holds itself would recurse without end."""
    loop: list[Any] = []
    loop.append(loop)
    view = _shown({"calling_ae_allowlist": {"AE1"}, "odd": loop})
    assert view["calling_ae_allowlist"] == ["AE1"]
    assert "***" in json.dumps(view["odd"])


# --- every view encodes ----------------------------------------------------------------------


def test_json_dumps_accepts_every_factory_view() -> None:
    """Every spec-returning factory, called with a probe in each credential parameter, gives a view
    ``json.dumps`` takes. The shape views above are each encoded by ``_shown``."""
    assert len(FACTORIES) > 20, (
        FACTORIES
    )  # the domain is 23 factories; an empty walk proves nothing
    for mod, name in FACTORIES:
        fn = _resolve(mod, name)
        assert fn is not None
        json.dumps(redacted_settings(dict(_call_with_sentinels(fn).settings)))
