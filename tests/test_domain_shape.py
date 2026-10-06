# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One domain-shape rule for three lists and the mail address check (vault BACKLOG #2843).

``[security].organization_domains``, ``[security].external_link_allowlist`` and
``[egress].allowed_recipient_domains`` each tested an entry's shape their own way, and the egress
list accepted hexadecimal IPv4 forms the address rule refuses. One table now feeds every list and
``envelope_address_problem`` the same values. The verdicts must agree, except for the one stated
difference: the two navigation lists also accept a canonical dotted-quad IPv4 address.

Read on the unfixed code at ``873aa9d75a``: ``organization_domains`` and
``external_link_allowlist`` accepted every value in :data:`_REFUSED` except the URL, port and
wildcard forms (``"."`` was dropped silently), and ``allowed_recipient_domains`` accepted
``example.org.``, ``10.0.0.0x1`` and ``0x7f000001``."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import EgressSettings, SecuritySettings
from messagefoundry.domainshape import domain_shape_problem
from messagefoundry.transports.email import envelope_address_problem
from messagefoundry_webconsole._external import is_allowlisted, is_external

#: Each list, and the settings section that validates it.
_MODELS: dict[str, type[SecuritySettings] | type[EgressSettings]] = {
    "organization_domains": SecuritySettings,
    "external_link_allowlist": SecuritySettings,
    "allowed_recipient_domains": EgressSettings,
}


def _load(list_name: str, value: str) -> list[str]:
    stored: list[str] = getattr(_MODELS[list_name].model_validate({list_name: [value]}), list_name)
    return stored


#: Values every list refuses, mapped to words of the shape rule's reason.
_REFUSED = {
    ".example.org": "empty label",
    "example.org.": "empty label",
    "example..org": "empty label",
    ".": "empty label",
    "-mx.example.org": "hyphen",
    "mx-.example.org": "hyphen",
    "x" * 64 + ".example.org": "longer than 63",
    ".".join(["x" * 63] * 4): "longer than 253",
    "example.123": "start with a letter",
    "0.1": "start with a letter",
    "010.0.0.1": "start with a letter",
    "10.0.0.0x1": "start with a letter",
    "0x7f000001": "start with a letter",
    "höspital.example": "non-ASCII",
    "mx_1.example.org": "not a host name",
    "https://example.org": "not a host name",
    "example.org:25": "not a host name",
    "*.example.org": "not a host name",
    "a@example.org": "not a host name",
}

#: Values every list accepts, each stored stripped and lowercased.
_ACCEPTED = [
    "example.org",
    "mail-relay.example.net",
    "mx1.example.org",
    "10.mail.example.com",
    "x" * 63 + ".example.org",
    "xn--bcher-kva.example.com",
    "  Example.ORG ",
]

#: The stated difference: a canonical IPv4 address is a navigation host, never a mail domain.
_IPV4 = "10.20.30.40"


@pytest.mark.parametrize("value", list(_REFUSED))
@pytest.mark.parametrize("list_name", list(_MODELS))
def test_every_list_refuses_the_same_values(list_name: str, value: str) -> None:
    with pytest.raises(ValidationError, match=_REFUSED[value]):
        _load(list_name, value)


@pytest.mark.parametrize("value", _ACCEPTED)
@pytest.mark.parametrize("list_name", list(_MODELS))
def test_every_list_accepts_the_same_values(list_name: str, value: str) -> None:
    assert _load(list_name, value) == [value.strip().lower()]


#: The values whose probe address reaches the domain check: one holding "@", "/", ":" or "*" fails
#: earlier, in the parse or the local part, so its verdict would agree for an unrelated reason.
#: The 255-character one is left out too: the address cap refuses it first.
_DOMAIN_ONLY = [
    v for v in [*_REFUSED, *_ACCEPTED, _IPV4] if not set(v) & set("@/:*") and len(v) < 250
]


@pytest.mark.parametrize("value", _DOMAIN_ONLY)
def test_the_address_check_agrees_with_the_recipient_list(value: str) -> None:
    # The send rule and the list a recipient is matched against give one verdict, so no entry is
    # accepted that no sendable address could match, and no sendable domain is unlistable.
    try:
        _load("allowed_recipient_domains", value)
        listed = True
    except ValidationError:
        listed = False
    assert (envelope_address_problem("a@" + value.strip()) is None) is listed


@pytest.mark.parametrize("list_name", ["organization_domains", "external_link_allowlist"])
def test_the_navigation_lists_take_a_canonical_ipv4_address(list_name: str) -> None:
    assert _load(list_name, _IPV4) == [_IPV4]


def test_the_recipient_list_refuses_an_ipv4_address() -> None:
    with pytest.raises(ValidationError, match="start with a letter"):
        _load("allowed_recipient_domains", _IPV4)


def test_the_console_matches_an_ipv4_entry_exactly() -> None:
    # Label-boundary matching is for domains. An address has no subdomains, so a host that merely
    # ends in the listed address is not covered. Control: the address itself is.
    entries = (_IPV4,)
    assert not is_external(f"https://{_IPV4}/", entries)
    assert is_allowlisted(f"https://{_IPV4}/", entries)
    assert is_external(f"https://x.{_IPV4}/", entries)
    assert not is_allowlisted(f"https://x.{_IPV4}/", entries)


def test_a_blank_entry_is_skipped_by_every_list() -> None:
    for list_name in _MODELS:
        assert _load(list_name, "   ") == []


@pytest.mark.parametrize("value", [*_REFUSED, ""])
def test_the_shared_reason_names_no_part_of_the_value(value: str) -> None:
    reason = domain_shape_problem(value)
    assert reason is not None
    for part in ("example", "mx", "0x", "spital", "xxx", "https", "25"):
        if part in value:
            assert part not in reason
