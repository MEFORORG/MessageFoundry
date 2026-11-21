# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``host[:port]`` allowlists refuse at load an entry no host can match, and the matcher
compares ports as numbers and reads a URL with no port at the port it dials (BACKLOG #5915).

On origin/main each of these loaded silently or matched on text: a malformed entry admitted
nothing, ``06661`` matched ``host:06661`` but not ``host:6661`` while the connector dials 6661, and
``https://host/`` did not match ``host:443`` although urllib dials 443 for it.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import AiSettings, EgressSettings
from messagefoundry.transports.ai_broker import endpoint_host_allowed
from messagefoundry.transports.egress import host_port_allowed, http_egress_allowed

_HOST_LISTS = (
    "allowed_mllp",
    "allowed_tcp",
    "allowed_http",
    "allowed_db",
    "allowed_remote",
    "allowed_smtp",
    "allowed_direct",
    "allowed_proxy",
    "allowed_syslog",
)

_MALFORMED = (
    "::1",
    "fe80::1:443",
    "[::1",
    "[::1]x",
    "[::1]8123",
    "[db.example.org]",
    "[127.0.0.1]",
    "[a:b]",
    "[]",
    ":443",
    "[::1]:",
    "db.example.org:",
    "db.example.org:abc",
    "db.example.org:0",
    "db.example.org:65536",
    "[fe80::1%eth0]",
    "[fe80::1%25eth0]:443",
    '["10.0.0.5"]',
    "https://user:secret@db.example.org/x",
    "api.example.org/fhir",
    "*.example.org",
    "relay@mail.example.org",
    "a b.example.org",
    "db.example.org;x",
    'db.example.org"',
)


@pytest.mark.parametrize("field", _HOST_LISTS)
@pytest.mark.parametrize("entry", _MALFORMED)
def test_malformed_entry_is_refused_at_load(field: str, entry: str) -> None:
    with pytest.raises(ValidationError, match=rf"\[egress\]\.{field} entry 2 is refused"):
        EgressSettings.model_validate({field: ["db.example.org", entry]})


def test_ai_endpoint_list_refuses_a_malformed_entry_at_load() -> None:
    with pytest.raises(ValidationError, match=r"\[ai\]\.allowed_endpoints entry 1 "):
        AiSettings(allowed_endpoints=["llm.internal:"])


def test_env_form_refuses_a_malformed_entry_at_load() -> None:
    with pytest.raises(ValidationError, match=r"\[egress\]\.allowed_http entry 2 "):
        EgressSettings(allowed_http="api.example.org, ::1")  # type: ignore[arg-type]


def test_refusal_does_not_quote_the_entry() -> None:
    with pytest.raises(ValidationError) as caught:
        EgressSettings(allowed_http=["https://user:hunter2@api.example.org"])
    assert "hunter2" not in str(caught.value)


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        ("http://h.example.org:8443", "is a URL or a path"),
        ("https://u:p%40ss@h.example.org", "is a URL or a path"),
        ("[fe80::1%eth0]", "zone id"),
        # Unbracketed, a zoned address is told about its zone, not to write [v6], which the
        # bracketed form above is refused for too.
        ("fe80::1%eth0", "zone id"),
        ("[fe80::1%eth0]:443", "zone id"),
        ("fe80::1:443", r"more than one ':' outside brackets"),
        ("*.example.org", "no pattern is read"),
        ("h.example.org:99999", "port is not a number"),
    ],
)
def test_refusal_names_the_reason(entry: str, reason: str) -> None:
    with pytest.raises(ValidationError, match=reason):
        EgressSettings(allowed_http=[entry])


@pytest.mark.parametrize("field", _HOST_LISTS)
def test_well_formed_entries_load_stripped(field: str) -> None:
    good = [
        " db.example.org ",
        "db.example.org:5432",
        "10.0.0.5:06661",
        "my_host",
        "xn--bcher-kva.example",
        "हिन्दी.example",  # Devanagari, with combining marks
        "café.example",  # a decomposed accent
    ]
    if field != "allowed_db":
        good += ["[::1]", "[2001:db8::10]:6661"]
    loaded = getattr(EgressSettings.model_validate({field: good}), field)
    assert loaded == [item.strip() for item in good]


@pytest.mark.parametrize("field", _HOST_LISTS)
@pytest.mark.parametrize("blank", ["", " "])
def test_blank_entry_is_refused_not_dropped(field: str, blank: str) -> None:
    # Dropped, a list of blanks would read as unset, which the audited opt-out reads as any host.
    with pytest.raises(ValidationError, match=r"entry 1 is refused: it is blank"):
        EgressSettings.model_validate({field: [blank], "deny_by_default": False})


def test_env_form_still_drops_blank_items() -> None:
    assert EgressSettings(allowed_http="a.example.org,, ,b.example.org").allowed_http == [  # type: ignore[arg-type]
        "a.example.org",
        "b.example.org",
    ]


# --- ports compare as numbers ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("port", "entry"),
    [
        ("06661", "h.example.org:6661"),
        ("6661", "h.example.org:6661"),
        (6661, "h.example.org:06661"),
        (" 6661 ", "h.example.org:6661"),
        ("6661", "[::1]:6661"),
    ],
)
def test_a_text_port_matches_the_entry_for_the_port_it_names(port: object, entry: str) -> None:
    host = "::1" if entry.startswith("[") else "h.example.org"
    assert host_port_allowed(host, port, [entry]) is True


@pytest.mark.parametrize("port", ["abc", "0", "99999", True, 6661.0, None, "6661x"])
def test_a_non_port_matches_only_an_entry_naming_no_port(port: object) -> None:
    assert host_port_allowed("h.example.org", port, ["h.example.org:6661"]) is False
    assert host_port_allowed("h.example.org", port, ["h.example.org"]) is True


def test_a_numeric_port_still_refuses_another_port() -> None:
    assert host_port_allowed("h.example.org", "06662", ["h.example.org:6661"]) is False


# --- a URL with no port is matched at the port urllib dials -------------------------------------


@pytest.mark.parametrize(
    ("url", "entry", "allowed"),
    [
        ("https://api.example.org/x", "api.example.org:443", True),
        ("http://api.example.org/x", "api.example.org:80", True),
        ("HTTPS://api.example.org/x", "api.example.org:443", True),
        ("https://[::1]/x", "[::1]:443", True),
        ("https://api.example.org/x", "api.example.org:80", False),
        ("http://api.example.org/x", "api.example.org:443", False),
        ("https://api.example.org:8443/x", "api.example.org:443", False),
        ("https://api.example.org/x", "api.example.org", True),
        ("ftp://api.example.org/x", "api.example.org:21", False),
    ],
)
def test_url_without_a_port_is_matched_at_its_dial_port(
    url: str, entry: str, allowed: bool
) -> None:
    assert http_egress_allowed(url, [entry]) is allowed
    assert endpoint_host_allowed(url, [entry]) is allowed
