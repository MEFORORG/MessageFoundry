# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A ``host[:port]`` allowlist entry: how one is read, and how a host and a port compare against it
(BACKLOG #5915).

One parse serves both sides of the rule. :mod:`messagefoundry.transports.egress` matches with it,
and :mod:`messagefoundry.config.settings` refuses at load every entry it cannot read, so an entry
that loads is one the matcher reads. The load refuses some entries the matcher does read as well,
at least a URL or a path, a host holding a character no host name does, and a port outside 1 to
65535: :func:`allow_entry_problem` says which. A leaf module at the package root for that reason: the settings
module may not import the transports package, which imports every connector. It imports nothing
outside the standard library.
"""

from __future__ import annotations

import ipaddress
import unicodedata

__all__ = [
    "HostKey",
    "allow_entry_problem",
    "canonical_host",
    "parse_allow_entry",
    "port_number",
    "port_or_zero",
]

#: A host as the allowlist compares it: an IP literal as an address, a name lowercased.
HostKey = ipaddress.IPv4Address | ipaddress.IPv6Address | str


def port_or_zero(text: str) -> int:
    """``text`` as a port number, or 0 when it is not one: the ONE definition of "is this a port"
    that the allowlist and :mod:`messagefoundry.transports.db_endpoint` use.

    A port is 1 to 65535, written in ASCII decimal digits, leading zeros allowed as drivers allow
    them. ``isdigit`` alone also passes a superscript digit, which ``int()`` then refuses with a
    ValueError. The five-digit bound, counted after the leading zeros, keeps ``int()`` away from
    CPython's string-to-int digit limit on an absurd operator value, which would turn a log detail
    into a crash."""
    text = text.strip()
    digits = text.lstrip("0")
    if not (text.isascii() and text.isdecimal() and len(digits) <= 5):
        return 0
    port = int(digits or "0")
    return port if port <= 65535 else 0


def port_number(value: object) -> int | None:
    """``value``, a port as a connection or a URL names it, as a number, or ``None`` when it is not
    one. An int is taken as it is and text is read by :func:`port_or_zero`, so a port that reaches
    a check as text, such as an uncast ``env()`` value, compares as the number the connector dials:
    ``06661`` is 6661. A bool, a float and anything outside 1 to 65535 are not a port."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 1 <= value <= 65535 else None
    if isinstance(value, str):
        return port_or_zero(value) or None
    return None


def canonical_host(text: str) -> HostKey | None:
    """``text``, a host as a connection names it, in the form the allowlist compares, or ``None``
    when no entry may match it.

    An IP literal compares as its address, so ``0:0:0:0:0:0:0:1`` is ``::1``. Anything else
    holding a ``:``, a bracketed ``[::1]`` included, matches no entry: no entry's host is such a
    name, and reading it as an address would be a guess about how its connector dials it. A name
    compares lowercased. Canonical equivalence only,
    never looser: an IPv4-mapped IPv6 address is not the IPv4 address, a trailing-dot name is not
    the dotless one, and shorthand IPv4 such as ``127.1`` is a name, since :mod:`ipaddress` reads
    only the dotted quad. A ``%`` zone id gets ``None``. :mod:`ipaddress` compares the zone, but a
    URL's zone is compared as written and dialled decoded: ``urlsplit`` reads ``[::1%31]`` as the
    host ``::1%31``, which an entry ``[::1%31]`` names, and ``urllib.request`` decodes it to
    ``::11`` before it dials, so the entry would admit a host it does not name."""
    if not text or "%" in text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None if ":" in text else text.lower()


def parse_allow_entry(entry: str) -> tuple[HostKey, str] | None:
    """``entry`` read as ``(host, port text)``, the port text ``""`` where it names none, or
    ``None`` for an entry that matches nothing.

    ``host``, ``host:port``, ``[v6]`` and ``[v6]:port`` are read. Brackets hold an IPv6 literal and
    nothing else. An unbracketed entry holding more than one ``:``, such as ``::1`` or
    ``fe80::1:443``, is ambiguous, so it matches nothing: the last group is never read as a port,
    and the entry is not read as a host with no port. A ``:`` with no port after it, such as
    ``[::1]:`` or ``db:`` (an ``env()`` that expanded to nothing), matches nothing too, rather
    than any port. The host is read by :func:`canonical_host`. The port text is returned as
    written; :func:`allow_entry_problem` says whether it is a port."""
    text = entry.strip()
    if text.startswith("["):
        close = text.find("]")
        if close == -1:
            return None
        inner, rest = text[1:close], text[close + 1 :]
        if (rest and not rest.startswith(":")) or ":" not in inner:
            return None
        host, sep, port = inner, rest[:1], rest[1:]
    elif text.count(":") > 1:
        return None
    else:
        host, sep, port = text.partition(":")
    port = port.strip()
    canonical = canonical_host(host.strip())
    if canonical is None or (sep and not port):
        return None
    return canonical, port


def _is_host_name(text: str) -> bool:
    """True if ``text`` holds only what a host name holds: letters, combining marks, digits,
    ``.``, ``-`` and ``_``. Any script passes, its marks included, so an internationalized name a
    connection writes unencoded is still listed as written."""
    return all(unicodedata.category(char)[0] in "LMN" or char in "._-" for char in text)


def allow_entry_problem(entry: str) -> str | None:
    """Why ``entry`` is refused when the settings load, or ``None`` when :func:`parse_allow_entry`
    reads it, its host is an IP address or holds only what :func:`_is_host_name` admits, and any
    port it names is a number from 1 to 65535.

    The reason never quotes the entry: an operator who pasted a URL, credential and all, would
    otherwise find it in the error."""
    text = entry.strip()
    if "://" in text or "@" in text or "/" in text:
        return "it is a URL or a path, not a host; list the host alone, with ':port' to pin a port"
    parsed = parse_allow_entry(text)
    if parsed is None:
        # Bracketed or not: an unbracketed zoned address would otherwise be told to write [v6],
        # and the bracketed form is refused too.
        if "%" in text:
            return "it carries a '%' zone id, which no host is matched with"
        if not text.startswith("[") and text.count(":") > 1:
            return "it holds more than one ':' outside brackets; write an IPv6 address as [v6]"
        return (
            "it is not 'host', 'host:port', '[v6]' or '[v6]:port': brackets hold an IPv6 address "
            "alone, and a ':' needs a port after it"
        )
    host, port = parsed
    if isinstance(host, str) and not _is_host_name(host):
        return (
            "its host holds a character no host name does, such as '*', ',' or a space; list "
            "each host by name, since no pattern is read"
        )
    if port and not port_or_zero(port):
        return "its port is not a number from 1 to 65535"
    return None
