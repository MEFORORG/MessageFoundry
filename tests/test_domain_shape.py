# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One domain-shape rule for three lists and the mail address check (vault BACKLOG #2843).

``[security].organization_domains``, ``[security].external_link_allowlist`` and
``[egress].allowed_recipient_domains`` each tested an entry's shape their own way, and the egress
list accepted hexadecimal IPv4 forms the address rule refuses. One table now feeds every list the
same values, and ``envelope_address_problem`` each value that reaches its domain check. The
verdicts must agree, except for two stated differences: the two navigation lists also accept a
canonical dotted-quad IPv4 address of one host, and the recipient list caps a domain at 252
characters, the most an address leaves, where the shape rule allows 253 (BACKLOG #3075).

Read on the unfixed code at ``873aa9d75a``: ``organization_domains`` and
``external_link_allowlist`` accepted every value in :data:`_REFUSED` except the URL, port and
wildcard forms (``"."`` was dropped silently), and ``allowed_recipient_domains`` accepted
``example.org.``, ``10.0.0.0x1`` and ``0x7f000001``."""

from __future__ import annotations

import ipaddress

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import EgressSettings, SecuritySettings
from messagefoundry.domainshape import domain_shape_problem, is_canonical_ipv4
from messagefoundry.transports.email import envelope_address_problem
from messagefoundry_webconsole import _external
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
    ".".join(["x" * 63] * 4): "longer than 25[23] characters",  # the recipient list caps at 252
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

#: Canonical quads that are no one host's address: unspecified, limited broadcast, multicast and
#: class E. Built from integers, so the file carries no routable literal for the leak scan.
_NOT_ONE_HOST = [str(ipaddress.IPv4Address(n)) for n in (0, 0xFFFF_FFFF, 0xE000_0001, 0xF000_0001)]


@pytest.mark.parametrize("value", list(_REFUSED))
@pytest.mark.parametrize("list_name", list(_MODELS))
def test_every_list_refuses_the_same_values(list_name: str, value: str) -> None:
    with pytest.raises(ValidationError, match=_REFUSED[value]):
        _load(list_name, value)


@pytest.mark.parametrize("value", _ACCEPTED)
@pytest.mark.parametrize("list_name", list(_MODELS))
def test_every_list_accepts_the_same_values(list_name: str, value: str) -> None:
    assert _load(list_name, value) == [value.strip().lower()]


#: The values whose probe address reaches the domain check. One holding "@", "/" or ":" fails the
#: read-back first, so its verdict would agree for an unrelated reason.
_DOMAIN_ONLY = [v for v in [*_REFUSED, *_ACCEPTED, _IPV4] if not set(v) & set("@/:")]

#: A 252-character domain, the longest an address can carry, and one a character longer.
_LONGEST_SENDABLE = ".".join(["x" * 63] * 3 + ["x" * 60])
_ONE_TOO_LONG = _LONGEST_SENDABLE + "x"


@pytest.mark.parametrize("value", [*_DOMAIN_ONLY, _LONGEST_SENDABLE, _ONE_TOO_LONG])
def test_the_address_check_agrees_with_the_recipient_list(value: str) -> None:
    # The send rule and the list a recipient is matched against give one verdict, so no entry is
    # accepted that no sendable address could match, and no sendable domain is unlistable.
    try:
        _load("allowed_recipient_domains", value)
        listed = True
    except ValidationError:
        listed = False
    assert (envelope_address_problem("a@" + value.strip()) is None) is listed


def test_the_recipient_list_refuses_a_domain_no_address_can_carry() -> None:
    """BACKLOG #3075: the shared rule allows 253 characters, the RFC 1035 limit, and the address
    cap of 254 leaves 252 for the domain. The list now caps it there, so the gap #2843 pinned is
    closed. Pinned to the send path, so a change to either cap is a decision rather than drift.

    Mutation: drop ``max_length`` from the recipient list's call. Red: DID NOT RAISE. The
    agreement test above also holds the list to the send path at both lengths."""
    assert len(_LONGEST_SENDABLE) == 252 and len(_ONE_TOO_LONG) == 253
    with pytest.raises(ValidationError, match="longer than 252 characters"):
        _load("allowed_recipient_domains", _ONE_TOO_LONG)
    # The other lists keep the shape rule's 253, which is a host a browser may open.
    assert _load("organization_domains", _ONE_TOO_LONG) == [_ONE_TOO_LONG]


@pytest.mark.parametrize("value", _NOT_ONE_HOST)
@pytest.mark.parametrize("list_name", ["organization_domains", "external_link_allowlist"])
def test_the_navigation_lists_refuse_an_address_that_is_not_one_host_s(
    list_name: str, value: str
) -> None:
    """BACKLOG #3075 item 7: the unspecified address, the limited broadcast, a multicast group and
    the reserved range are canonical dotted quads but no one host's address. ``0.0.0.0`` reaches the
    local machine in some browsers, so as an entry it would mark a loopback page as internal. The
    console and the engine still agree that each is an IPv4 entry; see the agreement test below.

    Mutation: return False from ``_not_a_host_address``. Red: DID NOT RAISE."""
    with pytest.raises(ValidationError, match="an IPv4 address that is not one host's"):
        _load(list_name, value)


def test_the_console_does_not_strip_a_leading_dot_from_an_entry() -> None:
    """BACKLOG #3075 item 5: settings refuse a dot-led entry at load, and the console stripped the
    dot from one that came another way, which only ever widened a match. Such an entry now covers
    nothing, so the interstitial shows. Control: the bare domain covers the host.

    Mutation: put ``.lstrip(".")`` back in ``_matches_domain``. Red: the first assertion."""
    url = "https://adfs.hospital.example/"
    assert is_external(url, [".hospital.example"])
    assert not is_allowlisted(url, [".hospital.example"])
    assert not is_external(url, ["hospital.example"])


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


@pytest.mark.parametrize(
    "value",
    [*_REFUSED, _IPV4, "10.20.30.040", *_NOT_ONE_HOST],
)
def test_the_console_and_the_engine_agree_on_what_is_an_ipv4_entry(value: str) -> None:
    # The console keeps its own stdlib check rather than import the engine module, so the two
    # must not drift: an entry would move between exact and label-boundary matching.
    assert _external._is_ipv4(value) is is_canonical_ipv4(value)


def test_a_blank_entry_is_skipped_by_every_list() -> None:
    for list_name in _MODELS:
        assert _load(list_name, "   ") == []


@pytest.mark.parametrize("value", [*_REFUSED, ""])
def test_the_shared_reason_names_no_part_of_the_value(value: str) -> None:
    reason = domain_shape_problem(value)
    assert reason is not None
    for part in ("example", "mx", "0x", "spital", "xxx", "https"):
        if part in value:
            assert part not in reason
