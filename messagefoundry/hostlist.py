# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A ``host[:port]`` allowlist entry: how one is read, and how a host and a port compare against it
(BACKLOG #5915), and the reading of a database ``server`` that names no host (BACKLOG #5512).

One parse serves both sides of the rule. :mod:`messagefoundry.transports.egress` matches with it,
and :mod:`messagefoundry.config.settings` refuses at load every entry it cannot read, so an entry
that loads is one the matcher reads. The load refuses some entries the matcher does read as well,
at least some URLs and paths, a host holding a character such as ``*``, ``,`` or a space, and a
port outside 1 to 65535: :func:`allow_entry_problem` says which.

A leaf module at the package root because one parse serves both: the settings module may not
import the transports package, which imports every connector. It imports nothing outside the
standard library.
"""

from __future__ import annotations

import ipaddress
import unicodedata

__all__ = [
    "HostKey",
    "allow_entry_problem",
    "canonical_host",
    "names_no_host",
    "parse_allow_entry",
    "port_number",
    "port_or_zero",
    "split_generic_server",
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
    """True if ``text`` holds only characters in the Unicode categories L (letters), M (marks)
    and N (numbers, not only ASCII digits: a superscript or a Roman numeral passes), and ``.``,
    ``-`` and ``_``. Any script passes, its marks included, so an internationalized name a
    connection writes unencoded is still listed as written."""
    return all(unicodedata.category(char)[0] in "LMN" or char in "._-" for char in text)


def _without_zone(text: str) -> str | None:
    """``text`` with its one ``%zone`` cut out, or ``None`` when it holds no ``%``, more than one,
    or a zone that, once stripped of blanks at either end, is empty or still holds a blank. The
    zone runs from the ``%`` to the next ``]`` or ``:``, even inside brackets. A ``%`` after the
    ``]`` is cut out too. An unbracketed address that holds a ``:`` comes back bracketed, so ``fe80::1%eth0:443``
    is ``[fe80::1]:443``; :func:`parse_allow_entry` then judges the rest. Nothing here reads the
    address itself."""
    if text.count("%") != 1:
        return None
    head, _, tail = text.partition("%")
    ends = [index for index in (tail.find("]"), tail.find(":")) if index != -1]
    end = min(ends, default=len(tail))
    zone, rest = tail[:end].strip(), tail[end:]
    if not zone or any(char.isspace() for char in zone):
        return None
    if head.startswith("["):
        return head + rest
    address = head.strip()
    return (f"[{address}]" if ":" in address else address) + rest


_HOST_CHARACTER_REASON = (
    "its host holds a character no host name does, such as '*', ',' or a space; list each host by "
    "name, since no pattern is read"
)


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
        # A '%' suffix is named only where cutting it out leaves an entry whose host is an IP
        # address, and a fault that bracketed entry has is named first. An unbracketed IPv6
        # address is bracketed before that check, so its missing brackets are named only on the
        # next load; told to write [v6] first, the operator would be refused for the zone then.
        unzoned = _without_zone(text)
        reread = parse_allow_entry(unzoned) if unzoned is not None else None
        if unzoned is not None and reread is not None and not isinstance(reread[0], str):
            return allow_entry_problem(unzoned) or (
                "its address carries a '%' suffix, such as an IPv6 zone id, which no host is "
                "matched with"
            )
        bracketed = text.startswith("[")
        if not bracketed and text.count(":") > 1:
            return "it holds more than one ':' outside brackets; write an IPv6 address as [v6]"
        if not bracketed and "%" in text.partition(":")[0]:
            # A name holding '%', such as a percent-encoded one, is no zoned address.
            return _HOST_CHARACTER_REASON
        return (
            "it is not 'host', 'host:port', '[v6]' or '[v6]:port': brackets hold an IPv6 address "
            "alone, and a ':' needs a port after it"
        )
    host, port = parsed
    if isinstance(host, str) and not _is_host_name(host):
        return _HOST_CHARACTER_REASON
    if port and not port_or_zero(port):
        return "its port is not a number from 1 to 65535"
    return None


def split_generic_server(server: str) -> tuple[str, str]:
    """Split a generic-dialect ``server`` into its host and the text after a port separator, which
    is ``""`` when it carries none and is not necessarily a port (:func:`port_or_zero` decides).

    ``host:port`` and ``[v6]:port`` are split. A bare IPv6 literal carries more than one colon and
    is left whole. A comma is NOT split on (BACKLOG #4874): libpq reads a comma in a host as a list
    of hosts, so the text before it need not be the only host dialled. Each caller deals with a
    comma before it gets here: the egress reading refuses it, and ``generic_hop_endpoint`` in
    :mod:`messagefoundry.transports.db_endpoint` reads it as its docstring says."""
    host = server.strip()
    in_server = ""
    if host.startswith("["):  # a bracketed IPv6 literal, optionally followed by ":port"
        close = host.find("]")
        if close != -1:
            host, rest = host[1:close], host[close + 1 :]
            in_server = rest[1:] if rest.startswith(":") else ""
    elif host.count(":") == 1:  # "host:port" — a bare IPv6 literal carries more than one colon
        host, _, in_server = host.partition(":")
    return host.strip(), in_server.strip()


_ONLY_PUNCTUATION_AND_DIGITS = frozenset("[]:0123456789")


def _entry_names_no_host(entry: str) -> bool:
    host = split_generic_server(entry)[0]
    if not host:
        return True
    # Text made only of brackets, colons and digits is a host only as an IPv6 literal or a plain
    # number, so `[`, `]` and `:1433:` name none. `::1` and `fe80::1` are literals and stay.
    if not set(host) <= _ONLY_PUNCTUATION_AND_DIGITS or host.isdigit():
        return False
    try:
        ipaddress.IPv6Address(host)
    except ValueError:
        return True
    return False


def names_no_host(server: str) -> bool:
    """Whether ``server`` names no host (BACKLOG #5512): it is blank, or an entry on either side
    of a comma is. An entry names none when it is empty, a bare port such as ``:1433``, empty
    brackets such as ``[]`` or ``[]:1433``, or text made only of brackets, colons and digits that
    is not an IPv6 literal, such as ``[``, ``]`` or ``:1433:``. A driver has to pick such a
    destination itself, so no reading here can place the hop.

    **At least these are not caught.** A single colon reads as ``host:port``, so a protocol prefix
    with nothing after it, such as ``tcp:``, counts as naming the host ``tcp``. Other text that is
    no host name is not judged either."""
    return any(_entry_names_no_host(entry) for entry in server.split(","))
