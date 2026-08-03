# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The ASVS 3.7.3 predicate: is this navigation leaving the organisation?

The interstitial itself is UI; this is the part that decides whether it appears, so it is the part
that has to be right. Two of these tests exist because the research on 3.7.3 named the exact ways a
naive implementation is worse than none: a suffix match without a label boundary admits the
attacker's lookalike, and a decoded IDN shows the operator a host that is not the one resolved.
"""

from __future__ import annotations

import pytest

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
    """The case that decides the SSO leg: Entra is trusted, and is not the hospital."""
    assert is_external("https://login.microsoftonline.com/tenant/oauth2/authorize", ORG) is True


# --- secure-by-default ------------------------------------------------------------------------


def test_with_no_org_domains_configured_everything_absolute_is_external() -> None:
    """An operator who configures nothing must get the notification, not silently get none."""
    assert is_external("https://adfs.hospital.example/x", []) is True


def test_relative_urls_are_never_external() -> None:
    """They cannot leave the origin, so warning on them would train click-through for nothing."""
    assert is_external("/ui/login", ORG) is False
    assert is_external("/ui/messages?q=1", []) is False


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


def test_an_empty_allowlist_exempts_nothing() -> None:
    """Reach control: the escape must do nothing until an operator opts in."""
    assert is_allowlisted("https://anything.example/", []) is False
