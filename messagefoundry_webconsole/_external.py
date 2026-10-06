# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

import ipaddress
import re
from urllib.parse import unquote, urlsplit

#: Schemes we will render an interstitial for. Anything else (``javascript:``, ``data:``, ``file:``)
#: is not a navigation we should be helping the operator complete, so callers treat it as a hard
#: refusal rather than as an external link to warn about.
NAVIGABLE_SCHEMES: frozenset[str] = frozenset({"http", "https"})

#: The WHATWG URL Standard's "special" schemes. For these, and for a scheme-less reference resolved
#: against this console's own https origin, a browser reads ``\\`` as ``/`` in the authority and the
#: path. Python's ``urlsplit`` does not, which is the gap :func:`_as_browser_reads` closes.
_SPECIAL_SCHEMES: frozenset[str] = frozenset({"http", "https", "ws", "wss", "ftp", "file"})

_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*:")

#: What a browser strips from both ends of a URL before parsing it: every C0 control and the space.
_C0_CONTROL_OR_SPACE = "".join(chr(c) for c in range(0x21))

#: What a browser deletes from ANYWHERE in a URL before parsing it.
_DROP_TAB_AND_NEWLINE = str.maketrans("", "", "\t\n\r")


def _as_browser_reads(url: str) -> str:
    """``url`` after the clean-up a browser applies before it decides where the URL goes.

    Three steps from the WHATWG URL Standard, each of which has been used to make a string look
    local to a server-side check while the browser navigates elsewhere: leading and trailing C0
    controls and spaces are stripped, tabs and newlines are deleted wherever they are, and for a
    special or scheme-less URL a backslash before the query is a slash. So ``/\\evil.example`` is
    ``//evil.example``, and ``https://evil.example\\@hospital.example/`` goes to ``evil.example``.
    """
    url = url.strip(_C0_CONTROL_OR_SPACE).translate(_DROP_TAB_AND_NEWLINE)
    scheme = _SCHEME_RE.match(url)
    if scheme is not None and scheme.group()[:-1].lower() not in _SPECIAL_SCHEMES:
        return url
    # The query and fragment keep their backslashes: only the authority and path read them as "/".
    end = min((i for i in (url.find("?"), url.find("#")) if i != -1), default=len(url))
    return url[:end].replace("\\", "/") + url[end:]


#: How many percent-decodings :func:`_is_origin_relative_path` follows before it gives up. Each
#: pass is linear in the URL, so an uncapped loop is quadratic in a ``%25`` chain; a URL still
#: changing after this many passes is classified external, which fails toward the interstitial.
_MAX_DECODE_PASSES = 4


def _is_origin_relative_path(normalised: str) -> bool:
    """Is ``normalised`` (already through :func:`_as_browser_reads`) a path on THIS origin?

    An ALLOWLIST of one shape, not a list of known-bad prefixes: ``/`` alone, or ``/`` and then
    anything but a separator. Every form that leaves the origin without a scheme (``//host``,
    ``/\\host``, ``\\\\host``, any of them behind whitespace or a control character) begins with
    two separators once :func:`_as_browser_reads` has run, so it fails the one test here.

    The test must also hold at every percent-decoding of the PATH, and the path must carry no
    ``.`` or ``..`` segment. A browser keeps ``/%2F%2Fevil.example`` and ``/.//evil.example`` on
    this origin, but a server or router that decodes the first, or removes dot segments from the
    second, before redirecting gets ``//evil.example``. Failing toward the interstitial costs one
    page, so neither shape is classified local.

    The path is cut from the query and fragment ONCE, before any decoding, because that is where a
    browser cuts it: a decoded ``%3F`` or ``%23`` is still path to the browser, so it must not
    hide the segments after it from the dot-segment check.
    """
    candidate = normalised.split("?", 1)[0].split("#", 1)[0]
    for _ in range(_MAX_DECODE_PASSES):
        if not candidate.startswith("/") or candidate[1:2] == "/":
            return False
        if any(segment in (".", "..") for segment in candidate.split("/")):
            return False
        # Whatever decodes the path reads every backslash in it as a separator.
        decoded = unquote(candidate).translate(_DROP_TAB_AND_NEWLINE).replace("\\", "/")
        if decoded == candidate:
            return True
        candidate = decoded
    return False


def _is_unnavigable(normalised: str) -> bool:
    """Is ``normalised`` NOT an http(s) navigation: a scheme outside :data:`NAVIGABLE_SCHEMES`, or
    a URL ``urlsplit`` cannot parse at all?

    A scheme-less reference has no scheme to judge. Either kind is never internal and never
    allowlisted: neither is a destination anyone should skip a warning for.
    """
    try:
        scheme = urlsplit(normalised).scheme.lower()
    except ValueError:
        # urlsplit raises on an invalid IPv6 literal, for one.
        return True
    return bool(scheme) and scheme not in NAVIGABLE_SCHEMES


def host_of(url: str) -> str:
    """The lowercase ASCII host of ``url``, or ``""`` if it has none we can trust.

    Returns the **IDNA/punycode** form deliberately — see the module docstring. A host that cannot be
    encoded (malformed IDN, empty label) returns ``""``, which every caller treats as *not internal*:
    failing toward showing the interstitial is the safe direction.
    """
    return _host_of_normalised(_as_browser_reads(url))


#: A host this module will compare: dot-separated labels of letters, digits, ``-`` and ``_``. Run
#: on the IDNA-encoded form, so an internationalised name has already become ``xn--`` labels.
_HOST_RE = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.?")

#: IDNA 2003 deviation characters: sharp s (both cases), final sigma, ZWNJ and ZWJ. Python's
#: ``idna`` codec maps them away (sharp s becomes ``ss``), and a browser's UTS 46 non-transitional
#: processing keeps them as an ``xn--`` label, so the two name different hosts. A host carrying
#: one is not one this module can name truthfully.
_IDNA_DEVIATIONS = frozenset("\u00df\u1e9e\u03c2\u200c\u200d")


def _host_of_normalised(normalised: str) -> str:
    """:func:`host_of` for a URL already through :func:`_as_browser_reads`."""
    try:
        # No strip(): whitespace or a control inside the host is refused by the grammar below,
        # as a browser refuses it, rather than trimmed into a host that looks internal.
        host = (urlsplit(normalised).hostname or "").lower()
    except ValueError:
        # urlsplit raises on things like an invalid IPv6 literal. Not parseable is not internal.
        return ""
    if not host or not _IDNA_DEVIATIONS.isdisjoint(host):
        return ""
    try:
        # ``encode("idna")`` rejects empty labels and over-long ones, which is why it is preferred
        # here over a bare ``str`` compare: it is the same normalisation the resolver will apply.
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""
    if _HOST_RE.fullmatch(ascii_host):
        # A trailing dot names the same host fully qualified; dropped so it matches its domain.
        return ascii_host.removesuffix(".")
    if _is_ipv6(ascii_host):
        return ascii_host
    # Percent-encoded bytes, controls or other punctuation: a browser decodes or refuses these
    # before it resolves, so the string here is not the host it would go to.
    return ""


def _is_ipv6(entry: str) -> bool:
    """Whether ``entry`` is an IPv6 address (``urlsplit`` strips the brackets from the host)."""
    try:
        ipaddress.IPv6Address(entry)
    except ValueError:
        return False
    return True


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
    An IPv4 entry, which ``[security]`` accepts in its canonical form, matches only that address:
    an address has no subdomains (vault BACKLOG #2843).
    """
    domain = domain.strip().lower().lstrip(".")
    if not domain or not host:
        return False
    if _is_ipv4(domain):
        return host == domain
    return host == domain or host.endswith("." + domain)


def _is_ipv4(entry: str) -> bool:
    """Whether ``entry`` is an IPv4 address. Stdlib rather than the engine's
    ``messagefoundry.domainshape``: this package is versioned apart from the engine, and the UI
    seam digest does not cover that module, so importing it could fail against an older engine."""
    try:
        ipaddress.IPv4Address(entry)
    except ValueError:
        return False
    return True


def is_external(url: str, organization_domains: list[str] | tuple[str, ...]) -> bool:
    """Does following ``url`` take the operator outside the organisation?

    ``True`` means *show the interstitial*. The default is deliberately biased that way: an empty
    ``organization_domains`` makes every absolute http(s) URL external, so an operator who configures
    nothing gets the notification rather than silently getting none.

    Only a path on this origin (``/ui/...``, see :func:`_is_origin_relative_path`) or an empty
    reference (this page) is classified local without looking at a host. A leading slash is NOT
    enough: ``//evil.example`` and ``/\\evil.example`` also start with one, and a browser takes both
    to ``evil.example`` (vault BACKLOG #2790). Every other reference, path-relative ones included,
    goes through the host check, and one with no host there is external.
    """
    normalised = _as_browser_reads(url)
    if not normalised or _is_origin_relative_path(normalised):
        return False
    if _is_unnavigable(normalised):
        # Not an http(s) navigation, or not parseable: never classified internal.
        return True
    host = _host_of_normalised(normalised)
    if not host:
        return True
    return not any(_matches_domain(host, d) for d in organization_domains)


def is_allowlisted(url: str, allowlist: list[str] | tuple[str, ...]) -> bool:
    """Has the operator explicitly exempted this destination from the interstitial?

    WARNING: This is the **audited escape**, and it lowers security by design: an allowlisted destination
    is navigated to with no notification and no cancel, which is precisely what ASVS 3.7.3 asks for.
    It exists because operators have legitimate high-traffic internal destinations on domains they
    do not want to declare wholesale. The serve gate warns when it is non-empty.

    Matched on the same label boundary as :func:`is_external`, for the same reason. A scheme that
    :func:`is_external` reports as external whatever its host (``javascript:``, ``data:``,
    ``file:``) is never exempted either: ``javascript://vendor.example/...`` has a hostname to
    ``urlsplit``, and the escape must not skip the warning for it.
    """
    normalised = _as_browser_reads(url)
    if _is_unnavigable(normalised):
        return False
    host = _host_of_normalised(normalised)
    if not host:
        return False
    return any(_matches_domain(host, d) for d in allowlist)


def display_host(url: str) -> str:
    """The host to SHOW the operator — ASCII, so it matches what the browser resolves."""
    return host_of(url) or "(unreadable destination)"
