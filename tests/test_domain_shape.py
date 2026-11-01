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

from messagefoundry.config.settings import EgressSettings, SecuritySettings, _not_a_host_address
from messagefoundry.domainshape import domain_shape_problem, is_canonical_ipv4, upn_suffix_key
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

#: Canonical quads that are no one host's address: unspecified, the rest of its ``0.0.0.0/8`` block
#: at both ends, limited broadcast, multicast and class E. Built from integers, so the file carries
#: no routable literal for the leak scan.
_NOT_ONE_HOST = [
    str(ipaddress.IPv4Address(n))
    for n in (0, 0x0001_0203, 0x00FF_FFFF, 0xFFFF_FFFF, 0xE000_0001, 0xF000_0001)
]

#: Addresses that must keep loading: the first after that block, the loopback address, which is
#: this machine's, the last before multicast, and a plain address.
_ONE_HOST = [
    *(str(ipaddress.IPv4Address(n)) for n in (0x0100_0000, 0x7F00_0001, 0xDFFF_FFFF)),
    _IPV4,
]


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
    """BACKLOG #3075 item 7: the ``0.0.0.0/8`` block, the limited broadcast, a multicast group and
    the reserved range are canonical dotted quads but no one host's address. ``0.0.0.0`` reaches the
    local machine in some browsers, so as an entry it would mark a loopback page as internal.
    BACKLOG #3765 item 7: the rest of that block, read by ``ipaddress`` as neither unspecified nor
    reserved, is refused the same way. The console and the engine still agree that each is an IPv4
    entry; see the agreement test below.

    Mutation: return False from ``_not_a_host_address``. Red: DID NOT RAISE."""
    with pytest.raises(ValidationError, match="an IPv4 address that is not one host's"):
        _load(list_name, value)


@pytest.mark.parametrize("value", _ONE_HOST)
@pytest.mark.parametrize("list_name", ["organization_domains", "external_link_allowlist"])
def test_the_navigation_lists_keep_an_address_that_is_one_host_s(
    list_name: str, value: str
) -> None:
    """The control for the refusal above: each edge of what it refuses stops where it should, and
    loopback, which is one machine's address and is documented as accepted, loads.

    Mutation: refuse ``0.0.0.0/7`` rather than ``/8``. Red: the first value."""
    assert _load(list_name, value) == [value]


@pytest.mark.parametrize("list_name", ["organization_domains", "external_link_allowlist"])
def test_a_bare_public_suffix_loads_as_a_single_label(list_name: str) -> None:
    """BACKLOG #3765 item 6, a pin of a stated decision and not a fix. ``com`` is one label, the
    shape of an intranet name, and telling the two apart would need the Public Suffix List. It loads
    and covers every host under it, as ``docs/CONFIGURATION.md`` tells the operator.

    Mutation: refuse a single label in ``_bare_domain_entries``. Red: this test."""
    assert _load(list_name, "com") == ["com"]
    assert not is_external("https://example.com/", ("com",))


@pytest.mark.parametrize("value", _NOT_ONE_HOST)
def test_the_console_refuses_an_entry_that_is_not_one_host_s_however_it_arrived(value: str) -> None:
    """BACKLOG #3765 item 8: settings refuse these at load, and an entry that reached the console
    another way matched its own address, so a URL to it skipped the interstitial, or was exempted
    by the allowlist. Such an entry now covers nothing, as a dot-led one does.

    Mutation: drop the ``_is_one_host`` test from ``_matches_domain``. Red: the first assertion."""
    url = f"https://{value}/"
    assert is_external(url, (value,))
    assert not is_allowlisted(url, (value,))


@pytest.mark.parametrize(
    ("address", "entry"),
    [
        (_NOT_ONE_HOST[0], "0"),
        (_NOT_ONE_HOST[0], "0.0"),
        (_NOT_ONE_HOST[0], "0.0.0"),
        (_IPV4, "40"),
        (_IPV4, "30.40"),
        ("0x0.0.0.0", "0.0"),
        ("00.0.0.0", "0.0"),
        ("0.0.0", "0.0"),
        ("[::ffff:0.0.0.0]", "0.0"),
    ],
)
def test_a_partial_entry_covers_no_address(address: str, entry: str) -> None:
    """BACKLOG #3765 item 8: ``0.0`` is no IPv4 entry, so it took a label-boundary match and covered
    ``0.0.0.0``. An address has no parent domain, so a host a browser reads as one takes no such
    match, whatever the entry looks like and however the host is spelled.

    Mutation: test only ``_is_ipv4(domain)`` in ``_matches_domain``. Red: every case."""
    url = f"https://{address}/"
    assert is_external(url, (entry,))
    assert not is_allowlisted(url, (entry,))


#: Spellings a browser reads as addresses and settings refuse: octal, hexadecimal and integer forms
#: of multicast and the limited broadcast, a short form, and IPv6 literals. Each entry is the host
#: the URL names, so an exact match would cover it.
_OTHER_SPELLINGS = [
    ("0340.0.0.1", "0340.0.0.1"),
    ("0xe0.0.0.1", "0xe0.0.0.1"),
    ("3758096385", "3758096385"),
    ("0xffffffff", "0xffffffff"),
    ("0", "0"),
    ("[::]", "::"),
    ("[ff02::1]", "ff02::1"),
]


@pytest.mark.parametrize(("host", "entry"), _OTHER_SPELLINGS)
def test_an_entry_covers_no_other_spelling_of_an_address(host: str, entry: str) -> None:
    """BACKLOG #3765 item 8: ``_is_ipv4`` reads only the canonical form, so these fell to the exact
    compare on the last line of ``_matches_domain`` and each entry covered its own spelling.

    Mutation: return ``False`` from ``_reads_as_address``. Red: every case."""
    url = f"https://{host}/"
    assert is_external(url, (entry,))
    assert not is_allowlisted(url, (entry,))


def test_the_console_and_the_engine_agree_on_which_addresses_are_one_host_s() -> None:
    """The console keeps its own copy of ``_not_a_host_address``, because importing the engine's
    could fail against an older engine. Compared at the first and last address of every ``/16``,
    so a new block of that size or larger in one copy turns this red; a smaller one might not.

    Mutation: drop any arm of either copy. Red: the first address of that arm's range."""
    verdicts = {}
    for first in range(0, 2**32, 2**16):
        for number in (first, first + 0xFFFF):
            value = str(ipaddress.IPv4Address(number))
            one_host = _external._is_one_host(value)
            assert one_host is not _not_a_host_address(value), value
            verdicts[one_host] = value
    assert set(verdicts) == {True, False}


def test_the_console_does_not_strip_a_leading_dot_from_an_entry() -> None:
    """BACKLOG #3075 item 5: settings refuse a dot-led entry at load, and the console stripped the
    dot from one that came another way, which only ever widened a match. Such an entry now covers
    nothing, so the interstitial shows. Control: the bare domain covers the host.

    Mutation: put ``.lstrip(".")`` back in ``_matches_domain``. Red: the first assertion."""
    url = "https://adfs.hospital.example/"
    assert is_external(url, [".hospital.example"])
    assert not is_allowlisted(url, [".hospital.example"])
    assert not is_external(url, ["hospital.example"])


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
    # must not drift. A host that reads as an address can match only if this says it is canonical:
    # read wider, a spelling settings refuse would cover itself, and read narrower, an address
    # settings accept would cover nothing.
    assert _external._is_ipv4(value) is is_canonical_ipv4(value)


@pytest.mark.parametrize("entry", ["Korp.example", " korp.example", "korp.example "])
def test_a_non_ascii_entry_covers_no_ascii_host(entry: str) -> None:
    """BACKLOG #3765, the class of item 9 on the console's side. ``str.lower()`` turned the Kelvin
    sign into an ASCII ``k`` and a plain ``strip()`` removed a non-ASCII space, so such an entry,
    which settings would refuse or strip at load, covered an ASCII host if it reached the console
    another way. Control: an ASCII entry's padding and capitals still go.

    Mutation: put ``domain.strip().lower()`` back in ``_matches_domain``. Red: every case.
    Mutation: ``_entry_key`` lower-cases every entry. Red: the first case.
    Mutation: ``_entry_key`` calls a plain ``strip()``. Red: the two white space cases."""
    url = "https://korp.example/"
    assert is_external(url, (entry,))
    assert not is_allowlisted(url, (entry,))
    assert not is_external(url, (" KORP.example\t",))


@pytest.mark.parametrize(
    "value", [" Corp.Example\t", "Korp.example", " corp.example", "MÜLLER.example"]
)
def test_the_console_and_the_engine_agree_on_the_compare_form(value: str) -> None:
    # The console's _entry_key is a copy of upn_suffix_key, kept for the reason _is_ipv4's docstring
    # gives, so a fix to one must not leave the other behind.
    assert _external._entry_key(value) == upn_suffix_key(value)


def test_the_upn_compare_form_accepts_nothing_that_lowering_both_sides_refused() -> None:
    """BACKLOG #3765 item 9: the OIDC suffix check moved from ``str.lower()`` on both sides to this
    form, and the move must only tighten it. So over every character that has another case, in
    each of its cases, bare and padded with an ASCII and a non-ASCII space: equal keys must mean
    equal ``str.strip().lower()`` results.

    Mutation: fold with ``casefold()`` in ``upn_suffix_key``. Red: a sharp s and ``ss``."""
    forms = {
        form
        for c in map(chr, range(0x11_0000))
        if c.lower() != c or c.upper() != c
        for form in (c, c.lower(), c.upper())
    }
    assert len(forms) > 2000  # every BMP cased letter, so a filter gone wrong cannot pass this
    by_key: dict[str, str] = {}
    for form in sorted(forms):
        for pad in ("", " ", chr(0xA0)):
            suffix = f"{pad}{form}.example"
            same_key = by_key.setdefault(upn_suffix_key(suffix), suffix)
            assert same_key.strip().lower() == suffix.strip().lower()


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
