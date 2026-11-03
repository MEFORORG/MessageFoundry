# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The host and port a DATABASE connection string names: the readings that the
``[egress].allowed_db`` check and the generic dialect's hop guard use, built on one split and one
port rule (vault BACKLOG #2704).

The two dialects send the port by different routes. The SQL Server preset writes the ``port``
setting into ``SERVER={server},{port}``. The generic dialect writes ``SERVER={server}`` and never
reads ``port``, so the only port it sends as a port is the ``PORT`` keyword in ``odbc_params``. An
allowlist entry that pins a port means something only while the check reads the port the connection
string sends, so :func:`database_dial_endpoint` reads it per dialect. What a driver does with that
string is outside this module: docs/CONNECTIONS.md says so once.

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


def _preset_port(value: object) -> int | None:
    """The ``port`` setting of the SQL Server preset as a port, or ``None``.

    ``_build_dsn`` reads the setting with ``transports.base.port_setting`` and writes that number
    into ``SERVER``. This applies ``int()`` only to an int, a float or a str, and not to a bool, and
    returns ``None`` for a value ``int()`` refuses or one outside 1 to 65535. So where both read a
    number, they read the same one: a whole float, a sign or a non-ASCII digit included. A bool, a
    fraction and an out-of-range number never reach a connection string, because ``port_setting``
    refuses them. This module cannot import that reader, so it keeps its own reading, and the two
    part on a port of 0 and on another numeric type, such as a whole ``Decimal``: the connection
    string sends a port there, and this reads none. Against a pinned entry that refuses the hop; a
    host-only entry admits it, as it admits any port."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        port = int(value)
    except (ValueError, OverflowError):
        return None
    return port if 1 <= port <= 65535 else None


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
    alone reads a port in the ``server`` text; the egress reading refuses such a ``server``."""
    host, in_server = split_generic_server(server)
    # A usable port in `server` wins; otherwise the PORT keyword; otherwise unknown. 0 is the "neither
    # said" value, so `or` reads correctly here — a port is never legitimately 0.
    keyword = str(odbc_param(params, "port") or "")
    return host, port_or_zero(in_server) or port_or_zero(keyword)


class DialEndpoint(NamedTuple):
    """The endpoint a DATABASE connection string names, as ``[egress].allowed_db`` reads it."""

    #: The ``server`` text, whole. The allowlist compares this with an entry's host.
    host: str
    #: The port the connection string sends, or ``None`` when the engine cannot read one. ``None``
    #: matches an entry that names no port, and never one that pins a port.
    port: int | None
    #: Why the reading itself refuses the hop, or ``None``. Set when a generic ``server`` holds a
    #: comma or a port, when ``odbc_params`` gives the ``PORT`` keyword more than once or with a
    #: leading zero, or when the SQL Server preset refuses the driver or the ``server``.
    conflict: str | None = None
    #: What the author should do when ``port`` is ``None`` and an entry pins a port, written to
    #: lead the refusal: the setting this dialect and driver read a port from.
    remedy: str = "set the port setting to the pinned port"


#: Words in an ``odbc_driver`` name that mark a driver the engine knows reads the ``PORT`` keyword:
#: psqlODBC, MySQL Connector/ODBC and MariaDB Connector/ODBC. A list of what is KNOWN, on purpose: a
#: name with none of these words reads no port, whatever driver it names.
_PORT_KEYWORD_DRIVERS = ("postgres", "psqlodbc", "mysql", "mariadb")

#: Words that mark a Microsoft SQL Server driver, which ignores ``PORT``. On the generic dialect
#: they win over the words above, so a name holding both reads no port; the SQL Server preset
#: refuses such a name (:func:`sqlserver_preset_refusal`).
_SQLSERVER_DRIVER_WORDS = ("msodbcsql", "sql server")


def _names_any(name: object, words: tuple[str, ...]) -> bool:
    """Whether ``odbc_driver``, as written and folded as :func:`odbc_keyword_name` folds it, holds
    any of ``words``: the one word test every driver reading in this module uses."""
    folded = odbc_keyword_name(str(name or ""))
    return any(word in folded for word in words)


def _sqlserver_driver_name(name: object) -> bool:
    """Whether ``odbc_driver``, as written, names a SQL Server driver
    (:data:`_SQLSERVER_DRIVER_WORDS`)."""
    return _names_any(name, _SQLSERVER_DRIVER_WORDS)


#: Words that mark the FreeTDS ODBC driver: its usual registered name, and its library,
#: ``libtdsodbc``. FreeTDS reads ``SERVER=host,port`` as a SQL Server driver does: its ODBC
#: ``parse_server`` takes a positive number after the last comma as the port, and looks the text
#: before it up as one host. A ``\`` in ``server`` turns that off: the text after it, comma and
#: port included, becomes an instance name, so the ``port`` setting is not sent as the port.
_FREETDS_DRIVER_WORDS = ("freetds", "tdsodbc")

#: The driver the SQL Server preset names when ``odbc_driver`` is not set.
SQLSERVER_DEFAULT_DRIVER = "ODBC Driver 18 for SQL Server"


def sqlserver_preset_refusal(settings: Mapping[str, Any]) -> str | None:
    """Why the SQL Server preset refuses to send ``SERVER={server},{port}`` for ``settings``, or
    ``None`` (BACKLOG #4873). The connection-string build and the ``[egress].allowed_db`` check
    both call it, so ``messagefoundry check`` refuses what the build would.

    The preset is only sound where the driver reads ``,port`` as the port and the text before it
    as one host, which the ``port`` pin and the host match both assume. psqlODBC passes ``SERVER``
    to libpq, which reads a comma as a host list, so ``db,6432`` there can name a second host the
    check never sees. So the ``odbc_driver`` name must hold a SQL Server word
    (:data:`_SQLSERVER_DRIVER_WORDS`) or a FreeTDS word (:data:`_FREETDS_DRIVER_WORDS`), and no
    word of a driver known to read ``PORT`` (:data:`_PORT_KEYWORD_DRIVERS`): a mixed name is
    refused, not read as SQL Server. The engine reads the name, not the library it loads.

    ``server`` must hold no comma, since the preset adds its own ``,port``; and on FreeTDS no
    ``\\``, which FreeTDS reads as an instance name in place of the port. Short, remedy first: a
    stored failure keeps about its first 200 characters."""
    driver = settings.get("odbc_driver", SQLSERVER_DEFAULT_DRIVER)
    if not _preset_driver(driver):
        return (
            'name a SQL Server driver, or on Database or DatabasePoll use dialect="generic": the '
            "preset sends server,port, which another driver can read as a host list"
        )
    server = str(settings.get("server", ""))
    if "," in server:
        return (
            f"name one host in server and put the port in the port setting: server {server!r} "
            "holds a comma, and the SQL Server preset adds its own ,port"
        )
    if "\\" in server and _names_any(driver, _FREETDS_DRIVER_WORDS):
        return (
            "name the host alone in server and set port to the instance's port: FreeTDS reads "
            f"an instance name in server {server!r} in place of the port setting"
        )
    return None


def _preset_driver(name: object) -> bool:
    """Whether the SQL Server preset accepts ``odbc_driver``, as written: it holds a SQL Server
    or FreeTDS word and no word of a driver known to read ``PORT``."""
    return not _names_any(name, _PORT_KEYWORD_DRIVERS) and (
        _sqlserver_driver_name(name) or _names_any(name, _FREETDS_DRIVER_WORDS)
    )


def _reads_port_keyword(name: object) -> bool:
    """Whether ``odbc_driver``, as written, names a driver the engine knows reads ``PORT``, in any
    case and spacing (:data:`_PORT_KEYWORD_DRIVERS`), and not a SQL Server driver.

    The engine reads the driver NAME, not the driver. An odbcinst alias or a library path is read
    by its words like any name; which library it loads is not visible here. A name that misdescribes
    its driver, such as a path holding ``mysql`` to a library that ignores ``PORT``, is outside what
    this check can catch."""
    return not _sqlserver_driver_name(name) and _names_any(name, _PORT_KEYWORD_DRIVERS)


def database_dial_endpoint(settings: Mapping[str, Any], *, dialect: str) -> DialEndpoint:
    """The host and port the connection string of a DATABASE connection built with ``dialect``
    names (vault BACKLOG #2704).

    ``dialect`` is the one the caller builds its connection string with, passed explicitly rather
    than read from ``settings``: the db_lookup executor and the DatabaseRef sync always build the SQL
    Server preset, whatever ``settings`` say.

    **The SQL Server preset** sends ``SERVER={server},{port}``, so the ``port`` setting is the port
    sent, defaulting to 1433 as the connection string does, read as :func:`_preset_port` says. A
    driver or a ``server`` the preset refuses (:func:`sqlserver_preset_refusal`) is a conflict.

    **The generic dialect** sends ``SERVER={server}`` and never reads the ``port`` setting, so it is
    ignored here. The port is the ``PORT`` keyword's, the one value the connection string sends as a
    port. A ``server`` holding a comma anywhere is refused: psqlODBC passes ``SERVER`` to libpq as
    a host, and libpq reads a comma there as a list of hosts, so ``db,6432`` or ``[db],6432`` can
    name a second host, and ``db,`` an empty one. A ``server`` carrying a ``:port`` or
    ``[v6]:port`` is refused too. ``PORT`` given twice, in any case, is refused, as the build
    refuses it, and so is a ``PORT`` value with a leading zero, which a driver could read as octal.
    With no usable ``PORT`` the port is ``None``: the engine does not know the port the driver then
    uses. The port is ``None`` too when the ``odbc_driver`` name, as written, is not one the
    engine knows reads ``PORT`` (:func:`_reads_port_keyword`, which says what a name cannot tell).
    The factory default, ``ODBC Driver 18 for SQL Server``, is one: the SQL Server drivers ignore
    ``PORT`` and dial their own default, and the generic dialect gives them no way to send a port,
    so for a SQL Server name the remedy names the SQL Server preset.

    The host is the whole ``server`` text on both dialects, as the check read it before this
    change, so an entry is matched on its host as written."""
    host = str(settings.get("server", ""))
    if dialect.lower() != "generic":
        return DialEndpoint(
            host,
            _preset_port(settings.get("port", SQLSERVER_DEFAULT_PORT)),
            conflict=sqlserver_preset_refusal(settings),
        )
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
    # Short, remedy early: a stored failure keeps about its first 200 characters.
    if "," in host:
        return DialEndpoint(
            host,
            None,
            conflict=(
                "name one host in server and put the port in the PORT keyword: "
                f"server {host!r} holds a comma, read as a port suffix or a host list"
            ),
        )
    if split_generic_server(host)[1]:
        return DialEndpoint(
            host,
            None,
            conflict=(
                f"server {host!r} carries a port: name the host alone and put the port in the "
                "PORT keyword"
            ),
        )
    text = str(keywords[0]).strip() if keywords else ""
    if len(text) > 1 and text.startswith("0") and text.isascii() and text.isdecimal():
        return DialEndpoint(
            host,
            None,
            conflict="give the PORT keyword without a leading zero: a driver can read it as octal",
        )
    driver = settings.get("odbc_driver")
    if not _reads_port_keyword(driver):
        # Point at the preset only for a name the preset accepts, so neither dialect's remedy
        # names the other for a mixed name that both refuse.
        sqlserver = _sqlserver_driver_name(driver) and _preset_driver(driver)
        return DialEndpoint(
            host,
            None,
            remedy=(
                "use dialect sqlserver, or a driver that reads the PORT keyword; a SQL Server "
                "driver ignores it"
                if sqlserver
                else "use a driver known to read the PORT keyword (psqlODBC, MySQL or MariaDB), "
                "or a host-only entry"
            ),
        )
    return DialEndpoint(
        host,
        (port_or_zero(text) or None) if keywords else None,
        remedy="set the PORT keyword to the pinned port",
    )
