# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ASVS 3.7.3 predicate: is this navigation leaving the organisation?

The interstitial itself is UI; this is the part that decides whether it appears, so it is the part
that has to be right. Two of these tests exist because the research on 3.7.3 named the exact ways a
naive implementation is worse than none: a suffix match without a label boundary admits the
attacker's lookalike, and a decoded IDN shows the operator a host that is not the one resolved.
"""

from __future__ import annotations

import pytest

from messagefoundry_webconsole import _external
from messagefoundry_webconsole._external import (
    display_host,
    host_of,
    is_allowlisted,
    is_external,
    is_idn_disguised,
)

ORG = ["hospital.example"]


# --- the label-boundary hole -----------------------------------------------------------------


def test_a_lookalike_domain_is_external_not_internal() -> None:
    """`evilhospital.example` ENDS WITH `hospital.example`. A bare endswith() calls it internal.

    This is the single most valuable test in the file: getting it wrong turns the allowlist into the
    attacker's tool, and the failure is silent — the operator sees no warning at all.
    """
    assert is_external("https://evilhospital.example/login", ORG) is True


def test_the_org_domain_itself_and_its_subdomains_are_internal() -> None:
    assert is_external("https://hospital.example/x", ORG) is False
    assert is_external("https://adfs.hospital.example/adfs/ls", ORG) is False
    assert is_external("https://deep.sub.hospital.example/x", ORG) is False


def test_a_third_party_idp_is_external() -> None:
    """The case that decides the SSO leg: the identity provider is trusted, and is not the hospital."""
    assert is_external("https://idp.example.com/tenant/oauth2/authorize", ORG) is True


# --- secure-by-default ------------------------------------------------------------------------


def test_with_no_org_domains_configured_everything_absolute_is_external() -> None:
    """An operator who configures nothing must get the notification, not silently get none."""
    assert is_external("https://adfs.hospital.example/x", []) is True


def test_absolute_paths_on_this_origin_are_not_external() -> None:
    """A path such as ``/ui/login`` cannot leave the origin, so warning on it would train
    click-through for nothing. Not every reference that starts with ``/`` is one: see below."""
    assert is_external("/ui/login", ORG) is False
    assert is_external("/ui/messages?q=1", []) is False


# --- what a browser takes off-origin (vault BACKLOG #2790) -------------------------------------
#
# The predicate used to call anything starting with "/" local. A browser takes several of those
# strings to another host, so each row below is a string a browser navigates to evil.example, and
# the first group is the two the review named. The benign table after it is the reach control: a
# predicate that called everything external would pass the hostile table alone.

_OFF_ORIGIN = [
    # Scheme-relative, and the backslash forms a browser reads as the same thing.
    "//evil.example/x",
    "/\\evil.example",
    "\\\\evil.example",
    "\\/evil.example",
    "//evil.example\\@hospital.example/",
    # Whitespace and control characters a browser strips or deletes before it parses.
    " //evil.example",
    "\t//evil.example",
    "\x00//evil.example",
    "\x1f/\\evil.example",
    "/\t/evil.example",
    "/\n/evil.example",
    "/\r\\evil.example",
    # Dot segments, which a server or router that normalises the path turns into "//evil.example".
    "/.//evil.example",
    "/./\\evil.example",
    "/%2e//evil.example",
    "/ui/../..//evil.example",
    # A decoded "?" or "#" is still path to the browser, so the dot segments after it count.
    "/%3F/%2e%2e/%2e%2e//evil.example",
    "/%23/%2e%2e//evil.example",
    "/ui%23/%2E%2E/%2E%2E//evil.example",
    # Encoded separators, which a server or router that decodes before redirecting would follow.
    "/%2F/evil.example",
    "/%2f%2fevil.example",
    "/%5Cevil.example",
    "/%252F%252Fevil.example",
    "/%09/evil.example",
    # Userinfo: the host is what follows the LAST "@" of the authority, not what precedes it.
    "//hospital.example@evil.example/",
    "https://hospital.example@evil.example/",
    "https://hospital.example:pw@evil.example/",
    # A backslash ends the authority for a browser and not for urlsplit, so these name evil.example.
    "https://evil.example\\@hospital.example/",
    "https:\\\\evil.example/",
    "HTTPS://evil.example\\hospital.example/",
]


@pytest.mark.parametrize("url", _OFF_ORIGIN)
def test_a_url_a_browser_takes_off_origin_is_external(url: str) -> None:
    assert is_external(url, ORG) is True


_SAME_ORIGIN = [
    "/",
    "/ui/login",
    "/ui/messages?q=1",
    "  /ui/login  ",
    "/ui/a\\b",  # a browser reads it as /ui/a/b, still this origin
    "/@evil.example",  # a path segment, not userinfo: there is no authority to put it in
    "/ui/x?next=//evil.example",  # the separators are in the query, after the path
    "/ui/x?next=%2F%2Fevil.example",
    "/ui/x#\\\\evil.example",
    "",  # an empty reference is this page
]


@pytest.mark.parametrize("url", _SAME_ORIGIN)
def test_a_path_on_this_origin_is_not_external(url: str) -> None:
    assert is_external(url, ORG) is False
    assert is_external(url, []) is False


def test_a_reference_that_is_not_an_absolute_path_fails_toward_external() -> None:
    """Allowlist shape: only ``/`` followed by a non-separator is local without a host check.

    A path-relative reference stays on this origin in a browser too, so calling it external costs
    one interstitial and nothing else. Pinned so a later widening of the local shape is deliberate.
    """
    assert is_external("ui/login", ORG) is True
    assert is_external("%2Fui/login", ORG) is True


def test_an_unparseable_url_is_external_rather_than_an_exception() -> None:
    """``urlsplit`` raises on an unclosed IPv6 literal. The predicate used to let that escape."""
    assert is_external("https://[::1/", ORG) is True
    assert is_allowlisted("https://[::1/", ["vendor.example"]) is False


def test_a_percent_chain_too_deep_to_follow_is_external() -> None:
    """The decode loop is capped, so a long ``%25`` chain costs a bounded number of passes and is
    classified external rather than followed to the end."""
    assert is_external("/%25" + "25" * 10_000 + "2F", ORG) is True
    assert is_external("/ui/x?q=%2541", ORG) is False  # two decodings: still followed


@pytest.mark.parametrize(
    "url",
    [
        "https://ma\u00dfhospital.example/",
        "https://\u03c2hospital.example/",
        "https://hospital\u200d.example/",
        "https://evil.example%2F.hospital.example/",
        "https://evil.example%00.hospital.example/",
    ],
)
def test_a_host_a_browser_reads_differently_is_never_internal(url: str) -> None:
    """Python's IDNA 2003 codec maps ``\u00df`` to ``ss`` where a browser keeps an ``xn--`` label,
    and a browser decodes ``%2F`` in a host that ``urlsplit`` keeps literally. Either way the string
    here is not the host navigated to, so it matches no domain and the allowlist exempts nothing."""
    domains = ["masshospital.example", "\u03c3hospital.example", "hospital.example"]
    assert host_of(url) == ""
    assert is_external(url, domains) is True
    assert is_allowlisted(url, domains) is False


@pytest.mark.parametrize(
    "url",
    [
        "https://adfs.hospital.example\x0b/",
        "https://\x0badfs.hospital.example/",
        "https://adfs.hospital.example\xa0/",
    ],
)
def test_whitespace_inside_a_host_is_refused_not_trimmed(url: str) -> None:
    """A browser refuses these URLs. Trimming them into an internal-looking host would not."""
    assert host_of(url) == ""
    assert is_external(url, ORG) is True


def test_a_fully_qualified_host_matches_its_domain() -> None:
    """A trailing dot names the same host. Reach control: the grammar must not make it external."""
    assert is_external("https://adfs.hospital.example./", ORG) is False
    assert is_allowlisted("https://docs.vendor.example./", ["vendor.example"]) is True


@pytest.mark.parametrize("host", ["a..b", ".a", ".", "a.b..", "", "a b", "a%2fb"])
def test_the_host_grammar_refuses_an_empty_label_and_stray_characters(host: str) -> None:
    """Pinned on the grammar itself: the IDNA codec usually refuses an empty label first, so a test
    through ``host_of`` alone would pass with the grammar's own refusal deleted."""
    assert _external._is_plain_host(host) is False
    assert host_of(f"https://{host}/") == ""


@pytest.mark.parametrize("host", ["a", "a.b", "a.b.", "x_y-1.example"])
def test_the_host_grammar_accepts_plain_labels(host: str) -> None:
    """Reach control for the refusals above."""
    assert _external._is_plain_host(host) is True


def test_an_ipv6_literal_still_has_a_host() -> None:
    """Reach control for the host grammar: an address literal is a host, not punctuation."""
    assert host_of("https://[2001:db8::1]/") == "2001:db8::1"


def test_host_of_reads_a_backslash_authority_the_way_a_browser_does() -> None:
    """The displayed host must be the one navigated to, and a browser ends the host at a backslash."""
    assert host_of("https://evil.example\\@hospital.example/") == "evil.example"
    assert display_host("https://evil.example\\@hospital.example/") == "evil.example"
    assert host_of(" https://hospital.example/") == "hospital.example"


@pytest.mark.parametrize(
    "url", ["javascript:alert(1)", "data:text/html,<b>x", "file:///etc/passwd"]
)
def test_non_navigable_schemes_are_refused_as_external(url: str) -> None:
    """Not a navigation we should help complete. Callers refuse; `True` keeps them out of the
    silent-pass branch."""
    assert is_external(url, ORG) is True


def test_an_unparseable_host_is_treated_as_external() -> None:
    """Fail toward showing the interstitial. `host_of` returning '' must never read as internal."""
    assert host_of("https://") == ""
    assert is_external("https://", ORG) is True


# --- the IDN homograph ------------------------------------------------------------------------


def test_an_idn_homograph_host_is_reported_in_punycode_not_unicode() -> None:
    """Cyrillic 'а' + 'mazon.com' renders identically to the Latin form.

    Showing the decoded Unicode would show the operator a host that is NOT the one resolved, which
    makes the interstitial actively misleading — worse than absent.
    """
    homograph = "https://аmazon.example/"
    assert display_host(homograph).startswith("xn--")
    assert display_host(homograph) != "amazon.com"
    assert is_idn_disguised(homograph) is True


def test_a_plain_ascii_host_is_not_flagged_as_disguised() -> None:
    """Negative control on the flag's REACH — without it, a warning that fires on everything
    carries no information."""
    assert is_idn_disguised("https://adfs.hospital.example/x") is False
    assert display_host("https://adfs.hospital.example/x") == "adfs.hospital.example"


def test_a_homograph_of_an_org_domain_is_still_external() -> None:
    """The two defences composed: the lookalike must not inherit the org's internal status."""
    assert is_external("https://hospital.examplе/x", ORG) is True  # Cyrillic 'о'


# --- the audited escape -----------------------------------------------------------------------


def test_the_allowlist_exempts_a_destination_and_respects_the_label_boundary() -> None:
    assert is_allowlisted("https://docs.vendor.example/help", ["vendor.example"]) is True
    assert is_allowlisted("https://notvendor.example/help", ["vendor.example"]) is False


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example\\@docs.vendor.example/",
        "https://docs.vendor.example.evil.example/",
        "//evil.example\\@docs.vendor.example/",
        "javascript://docs.vendor.example/%0Aalert(1)",
        "data://docs.vendor.example/,x",
    ],
)
def test_the_allowlist_does_not_exempt_a_url_that_goes_elsewhere(url: str) -> None:
    """The escape skips the warning, so a string it misreads skips it for the attacker's host."""
    assert is_allowlisted(url, ["vendor.example"]) is False


def test_the_allowlist_still_exempts_a_scheme_relative_url_to_its_domain() -> None:
    """Reach control for the scheme refusal above: a scheme-relative URL is http(s) here."""
    assert is_allowlisted("//docs.vendor.example/help", ["vendor.example"]) is True


def test_an_empty_allowlist_exempts_nothing() -> None:
    """Reach control: the escape must do nothing until an operator opts in."""
    assert is_allowlisted("https://anything.example/", []) is False
