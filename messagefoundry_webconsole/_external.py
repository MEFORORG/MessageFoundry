# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Is this navigation leaving the organization, and what host do we tell the operator it goes to?

ASVS 3.7.3 asks for a notification, with a cancel, when the user is sent to a URL **outside the
application's control**. Control is *organisational*, not topological: a hospital's own AD FS is a
different host, a different origin, and still squarely inside the operator's control. So the test here
is a declared domain list (``[security].organization_domains``), not same-origin.

**Everything in this module is pure.** No settings import, no request, no I/O — the predicate is the
part that has to be right, and it is the part worth testing exhaustively.

Two failure modes drove the details, both from the 3.7.3 research:

* **A suffix test without a dot boundary is a hole.** ``evilhospital.example`` ends with ``hospital.example``.
  Matching must be on a label boundary or the allowlist silently admits the attacker's lookalike.
* **The displayed host must be what the browser will actually resolve.** An IDN homograph
  (Cyrillic ``а`` in ``аmazon.example``) renders identically to the Latin form, so showing the decoded
  Unicode is showing the operator a lie. We display the **punycode/ASCII** form, which is what DNS
  gets, and say so when the two differ.
"""

from __future__ import annotations

from urllib.parse import urlsplit

#: Schemes we will render an interstitial for. Anything else (``javascript:``, ``data:``, ``file:``)
#: is not a navigation we should be helping the operator complete, so callers treat it as a hard
#: refusal rather than as an external link to warn about.
NAVIGABLE_SCHEMES: frozenset[str] = frozenset({"http", "https"})


def host_of(url: str) -> str:
    """The lowercase ASCII host of ``url``, or ``""`` if it has none we can trust.

    Returns the **IDNA/punycode** form deliberately — see the module docstring. A host that cannot be
    encoded (malformed IDN, empty label) returns ``""``, which every caller treats as *not internal*:
    failing toward showing the interstitial is the safe direction.
    """
    try:
        host = (urlsplit(url).hostname or "").strip().lower()
    except ValueError:
        # urlsplit raises on things like an invalid IPv6 literal. Not parseable is not internal.
        return ""
    if not host:
        return ""
    try:
        # ``encode("idna")`` rejects empty labels and over-long ones, which is why it is preferred
        # here over a bare ``str`` compare: it is the same normalisation the resolver will apply.
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""


def is_idn_disguised(url: str) -> bool:
    """True when the host renders as one thing and resolves as another.

    A homograph attack is invisible by construction — that is its whole point — so the interstitial
    needs to say "this is not the ASCII you think it is" rather than rely on the operator spotting a
    Cyrillic ``а``. Any host that survives IDNA encoding into a ``xn--`` label qualifies.
    """
    return "xn--" in host_of(url)


def _matches_domain(host: str, domain: str) -> bool:
    """``host`` is ``domain`` or a subdomain of it — matched on a LABEL boundary.

    ``evilhospital.example`` must not match ``hospital.example``. A plain ``endswith`` says it does.
    """
    domain = domain.strip().lower().lstrip(".")
    if not domain or not host:
        return False
    return host == domain or host.endswith("." + domain)


def is_external(url: str, organization_domains: list[str] | tuple[str, ...]) -> bool:
    """Does following ``url`` take the operator outside the organisation?

    ``True`` means *show the interstitial*. The default is deliberately biased that way: an empty
    ``organization_domains`` makes every absolute http(s) URL external, so an operator who configures
    nothing gets the notification rather than silently getting none.

    Relative URLs (``/ui/...``) are never external — they cannot leave the origin.
    """
    if not url or url.startswith("/"):
        return False
    scheme = urlsplit(url).scheme.lower()
    if scheme and scheme not in NAVIGABLE_SCHEMES:
        # Not a navigation we warn about; callers refuse these outright.
        return True
    host = host_of(url)
    if not host:
        return True
    return not any(_matches_domain(host, d) for d in organization_domains)


def is_allowlisted(url: str, allowlist: list[str] | tuple[str, ...]) -> bool:
    """Has the operator explicitly exempted this destination from the interstitial?

    ⚠️ This is the **audited escape**, and it lowers security by design: an allowlisted destination
    is navigated to with no notification and no cancel, which is precisely what ASVS 3.7.3 asks for.
    It exists because operators have legitimate high-traffic internal destinations on domains they
    do not want to declare wholesale. The serve gate warns when it is non-empty.

    Matched on the same label boundary as :func:`is_external`, for the same reason.
    """
    host = host_of(url)
    if not host:
        return False
    return any(_matches_domain(host, d) for d in allowlist)


def display_host(url: str) -> str:
    """The host to SHOW the operator — ASCII, so it matches what the browser resolves."""
    return host_of(url) or "(unreadable destination)"
