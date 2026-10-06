# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one domain-shape rule (vault BACKLOG #2843).

The mail address check in ``transports/email.py`` (``envelope_address_problem``),
``[egress].allowed_recipient_domains``, ``[security].organization_domains`` and
``[security].external_link_allowlist`` all call :func:`domain_shape_problem`. Each caller keeps
its own normalisation and its own matching, and says what they are in its own docstring.

**Neutral and stdlib-only**, so ``config/`` and ``transports/`` can both import it without a cycle:
``transports/email.py`` already imports ``config.settings``, so the rule cannot live in either.
It sits at the package root beside the other neutral leaves, such as ``netaddr`` and
``controlchars``.
"""

from __future__ import annotations

import ipaddress
import string

__all__ = ["domain_shape_problem", "is_canonical_ipv4"]

#: The characters a hostname-shaped domain may hold, in either case.
_DOMAIN_TEXT = frozenset(string.ascii_letters + string.digits + "-.")
#: The RFC 1035 limits on one label of a domain, and on the whole domain written without a final dot.
_MAX_LABEL = 63
_MAX_DOMAIN = 253


def domain_shape_problem(domain: str) -> str | None:
    """Why ``domain`` is not a hostname-shaped domain, or ``None`` when it is.

    Hostname-shaped means ASCII labels of letters, digits and hyphens, 1 to 63 characters each,
    none starting or ending with a hyphen, and 253 characters in all. So an empty domain, an empty label, and a leading,
    trailing or doubled dot, are refused. The last label must start with a letter. That refuses a
    dotted quad, and also the forms ``inet_aton`` reads as IPv4, such as ``10.0.0.0x1`` and
    ``0x7f000001``, which an all-digits test would pass. No public top-level domain starts with a
    digit, so this refuses no public domain. A private DNS name whose last label starts with a
    digit is refused too (vault BACKLOG #2911, a Manager decision under the owner's driver rule).
    A non-ASCII domain is refused; its ``xn--`` form passes.

    The check ignores case and strips nothing; the caller decides both. The reason is a noun
    phrase that names no part of the value, so a caller can put it after "has" or "is" in a
    message without echoing what it checked."""
    if not domain.isascii():
        return "a non-ASCII domain; write it in its ASCII xn-- form"
    if set(domain) - _DOMAIN_TEXT:
        return "a domain that is not a host name"
    labels = domain.split(".")
    if not all(labels):
        return "a domain with an empty label, or a dot at its start or end"
    if len(domain) > _MAX_DOMAIN:
        return f"a domain longer than {_MAX_DOMAIN} characters"
    if any(len(label) > _MAX_LABEL for label in labels):
        return f"a domain label longer than {_MAX_LABEL} characters"
    if any(label[0] == "-" or label[-1] == "-" for label in labels):
        return "a domain label that starts or ends with a hyphen"
    if labels[-1][0] not in string.ascii_letters:
        return "a domain whose last label does not start with a letter, as in an IP address"
    return None


def is_canonical_ipv4(text: str) -> bool:
    """Whether ``text`` is an IPv4 address written as four decimal octets with no leading zeros.

    The one form besides a domain that ``[security].organization_domains`` and
    ``external_link_allowlist`` accept, and that the console matches exactly rather than on a
    label boundary. A short, octal or hexadecimal form is not canonical."""
    try:
        return str(ipaddress.IPv4Address(text)) == text
    except ValueError:
        return False
