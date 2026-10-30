# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Where a DATABASE connection dials: the readings of its host and port that the
``[egress].allowed_db`` check and the generic dialect's hop guard use, built on one split and one
port rule (vault BACKLOG #2704).

The two dialects send the port by different routes. The SQL Server preset writes the ``port``
setting into ``SERVER={server},{port}``. The generic dialect writes ``SERVER={server}`` and never
reads ``port``, so the only port it sends as a port is the ``PORT`` keyword in ``odbc_params``. An
allowlist entry that pins a port means something only while the check reads the port the driver is
sent, so :func:`database_dial_endpoint` reads it per dialect.

A leaf module on purpose. :mod:`messagefoundry.transports.egress` and
:mod:`messagefoundry.transports.database` both read it, and it imports neither, so neither has to
import the other to share it. It imports nothing outside the standard library.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NamedTuple

#: The port the SQL Server preset's connection string uses when ``port`` is not set.
SQLSERVER_DEFAULT_PORT = 1433


def odbc_keyword_name(key: str) -> str:
    """``key`` in the form the keyword lists are compared in: lower case. ODBC keywords are
    case-insensitive, so two spellings a driver reads as the same keyword must not get two answers.
    Blanks are folded too, which matters only for a key the build's keyword check has not seen.

    A refusal prints this form and not the operator's spelling. The log scrub reads two capitalised
    words as a name and blanks them, which would leave a two-word keyword out of its own refusal."""
    return " ".join(key.split()).lower()


def odbc_param(params: Mapping[str, Any], keyword: str) -> object | None:
    """The value ``params`` gives ``keyword``, matched as the build matches it, or ``None``."""
    return next((v for k, v in params.items() if odbc_keyword_name(str(k)) == keyword), None)


def port_or_zero(text: str) -> int:
    """``text`` as a port number, or 0 when it is not one: the ONE definition of "is this a port",
    used by every reading in this module.

    A port is 1 to 65535, written in ASCII decimal digits. ``isdigit`` alone also passes a superscript
    digit, which ``int()`` then refuses with a ValueError. The five-character bound keeps ``int()``
    away from CPython's string-to-int digit limit on an absurd operator value, which would turn a
    log detail into a crash."""
    text = text.strip()
    if not (text.isascii() and text.isdecimal() and len(text) <= 5):
        return 0
    port = int(text)
    return port if port <= 65535 else 0


def split_generic_server(server: str) -> tuple[str, str]:
    """Split a generic-dialect ``server`` into its host and the text after a port separator, which
    is ``""`` when it carries none and is not necessarily a port (:func:`port_or_zero` decides).

    ``host,port`` (the SQL Server spelling), ``host:port``, and ``[v6]:port`` are split. A bare IPv6
    literal carries more than one colon and is left whole."""
    host = server.strip()
    in_server = ""
    if host.startswith("["):  # a bracketed IPv6 literal, optionally followed by ":port"
        close = host.find("]")
        if close != -1:
            host, rest = host[1:close], host[close + 1 :]
            in_server = rest[1:] if rest.startswith(":") else ""
    elif "," in host:  # the SQL-Server-style "host,port"
        host, _, in_server = host.partition(",")
    elif host.count(":") == 1:  # "host:port" — a bare IPv6 literal carries more than one colon
        host, _, in_server = host.partition(":")
    return host.strip(), in_server.strip()


def generic_hop_endpoint(server: str, params: Mapping[str, Any]) -> tuple[str, int]:
    """Split a generic-dialect ``server`` setting into ``(host, port)`` for the hop guard.

    The loopback carve-out is decided on the HOST alone and
    :func:`~messagefoundry.config.tls_policy.is_loopback_hop_host` never resolves DNS, so a
    ``host,port`` / ``host:port`` / ``[v6]:port`` suffix has to come off first: left on,
    ``"127.0.0.1,5432"`` parses as a name rather than an address, is treated as remote, and a genuinely
    on-box dev hop is refused.

    A port the ``server`` string does not carry is read from the documented generic ``PORT`` keyword,
    and falls back to 0 when neither says. In the hop guard the port is report-only: it never changes
    the disposition there.

    **The reading is a control input now (vault BACKLOG #2704).** The split and the port rule here
    are the ones :func:`database_dial_endpoint` reads for ``[egress].allowed_db``, through
    :func:`split_generic_server` and :func:`port_or_zero`. A change to either changes what that
    allowlist admits, so it is reviewed as a change to a control, not to a log line. This function
    alone lets a port in the ``server`` text win; the egress reading takes the port from the
    keyword only, and refuses a ``server`` port that disagrees with it."""
    host, in_server = split_generic_server(server)
    # A usable port in `server` wins; otherwise the PORT keyword; otherwise unknown. 0 is the "neither
    # said" value, so `or` reads correctly here — a port is never legitimately 0.
    keyword = str(odbc_param(params, "port") or "")
    return host, port_or_zero(in_server) or port_or_zero(keyword)


class DialEndpoint(NamedTuple):
    """The endpoint a DATABASE connection's settings dial, as ``[egress].allowed_db`` reads it."""

    #: The ``server`` text, whole. The allowlist compares this with an entry's host.
    host: str
    #: The port the driver is sent, or ``None`` when the engine cannot read one. ``None`` matches an
    #: entry that names no port, and never one that pins a port.
    port: object | None
    #: Why the port reading itself refuses the hop, or ``None``. Set when the generic dialect is
    #: given the ``PORT`` keyword more than once, or a port in ``server`` that ``PORT`` does not
    #: name.
    conflict: str | None = None


def database_dial_endpoint(settings: Mapping[str, Any], *, dialect: str) -> DialEndpoint:
    """The host and port a DATABASE connection built with ``dialect`` dials (vault BACKLOG #2704).

    ``dialect`` is the one the caller builds its connection string with, passed explicitly rather
    than read from ``settings``: the db_lookup executor and the DatabaseRef sync always build the SQL
    Server preset, whatever ``settings`` say.

    **The SQL Server preset** sends ``SERVER={server},{port}``, so the ``port`` setting is what is
    dialled, defaulting to 1433 as the connection string does.

    **The generic dialect** sends ``SERVER={server}`` and never reads the ``port`` setting, so it is
    ignored here. The port is the ``PORT`` keyword's, the one value the connection string sends as a
    port. A port in the ``server`` text is not read as the port: psqlODBC passes ``SERVER`` to libpq
    as a host and does not parse a ``,port`` in it, so the driver may dial its default port instead.
    Where ``server`` carries one, ``PORT`` must name the same port, or the reading refuses: which
    one the driver honours is not measured. ``PORT`` given twice, in any case, is refused too, as
    the build refuses it. With no usable ``PORT`` the port is ``None``: the driver's default port is
    not known to the engine.

    The host is the whole ``server`` text on both dialects, as the check read it before this change.
    A port suffix is not taken off the host here. libpq reads a comma in a host as a list of hosts,
    so ``db,6432`` can name a second host, and admitting it on an entry for ``db`` would loosen the
    host binding (an entry is matched on host as written)."""
    host = str(settings.get("server", ""))
    if dialect.lower() != "generic":
        return DialEndpoint(host, settings.get("port", SQLSERVER_DEFAULT_PORT))
    params = settings.get("odbc_params")
    # A table that is not a mapping is the build's own refusal; read it as giving no keyword.
    keywords = [
        value
        for key, value in (params.items() if isinstance(params, Mapping) else ())
        if odbc_keyword_name(str(key)) == "port"
    ]
    if len(keywords) > 1:
        return DialEndpoint(
            host, None, conflict="odbc_params gives the PORT keyword more than once; give it once"
        )
    keyword = port_or_zero(str(keywords[0])) if keywords else None
    in_server = split_generic_server(host)[1]
    if in_server and keyword is not None and port_or_zero(in_server) != keyword:
        return DialEndpoint(
            host,
            None,
            conflict=(
                f"server {host!r} names a port in its text and the PORT keyword in odbc_params "
                "names another, or one of them is not a port; the engine cannot tell which one "
                "the driver dials, so give the port once, in the PORT keyword"
            ),
        )
    return DialEndpoint(host, keyword or None)
