# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The endpoint-URL credential screen, with no engine import (vault BACKLOG #3533 item 14).

:func:`refuse_url_credentials` and the uncached ``urlsplit`` it reads through moved here from
``transports/rest.py`` and ``transports/proxy_address.py``, so ``config`` can run the same screen
at settings load without importing the transports package, whose ``__init__`` registers every
connector. ``rest`` and ``proxy_address`` import them back, so their names are unchanged.

Imports only the standard library.
"""

from __future__ import annotations

import inspect
import urllib.parse
from collections.abc import Callable

#: ``urlsplit`` without its ``functools.lru_cache`` layer, so a split here adds no key to the
#: process-wide cache (vault BACKLOG #3454, #5287). ``transports/proxy_address.py`` says what that
#: does and does not keep out of the cache.
UNCACHED_URLSPLIT: Callable[[str], urllib.parse.SplitResult] = inspect.unwrap(urllib.parse.urlsplit)

# WP-L3-09 (ASVS 4.2.5): bound the resolved outbound URL at construction. ``transports/rest.py``
# bounds the header values beside it and says why 8 KiB.
MAX_OUTBOUND_URL_LEN = 8192


#: Where a refusal tells the operator to put an endpoint's credential instead of its URL.
_URL_CREDENTIAL_USE = "basic_user/basic_password or bearer_token"


def _port_fields(netloc: str) -> tuple[str, ...]:
    """Every port field a reader takes from ``netloc``; empty when no reader sees a port.

    Two readers, because they disagree. ``urlsplit`` reads the RAW authority, after an IPv6
    literal's ``]`` or else after the first ``:``. urllib unquotes the host before ``http.client``
    reads it, after the last ``:`` that follows any ``]``. So ``svc%3A12`` dials port 12, and
    ``svc:ab%5Dc`` hides its port from ``http.client`` alone. The caller has refused userinfo."""
    fields: list[str] = []
    raw = netloc.partition("]")[2] if netloc.startswith("[") else netloc
    if ":" in raw:
        fields.append(raw.partition(":")[2])
    dial = urllib.parse.unquote(netloc)
    colon = dial.rfind(":")
    if colon > dial.rfind("]"):
        fields.append(dial[colon + 1 :])
    return tuple(fields)


def _is_port(value: str) -> bool:
    """Is ``value`` empty or a number from 0 to 65535? Leading zeros count, since ``urlsplit`` and
    ``http.client`` both accept them. The length is capped before ``int``, so nothing raises."""
    digits = value.lstrip("0")
    return value == "" or (
        value.isascii() and value.isdigit() and len(digits) <= 5 and int(digits or "0") <= 65535
    )


def _host_holds_encoded_colon(p: urllib.parse.SplitResult) -> bool:
    """Does an unbracketed host hold ``:`` once unquoted? No host name holds one."""
    return not p.netloc.rpartition("@")[2].startswith("[") and ":" in urllib.parse.unquote(
        p.hostname or ""
    )


def refuse_url_credentials(
    url: str,
    setting: str,
    *,
    use: str = _URL_CREDENTIAL_USE,
    error: type[ValueError] = ValueError,
) -> None:
    """Refuse an endpoint URL that carries a credential, at CONSTRUCTION time (BACKLOG #1793).

    WHY IT IS REFUSED RATHER THAN SUPPORTED. urllib never turns URL userinfo into an ``Authorization``
    header. It hands ``user:pw@host`` to ``http.client`` as the HOST, which reads ``pw@host`` as the
    port and raises ``InvalidURL("nonnumeric port: 'pw@host'")``. With an explicit port the lookup fails
    on a host that still holds the password, and through a plain-http forward proxy the password goes
    out in the request line and the ``Host`` header. So the shape never authenticated anything, and its
    error text carried the password into ``queue.last_error`` and the test-connection reply.

    At least three shapes are refused, all read after unquoting, because urllib unquotes the host: so
    ``%40`` leaks exactly like ``@`` and ``%3A`` names a port like ``:``. An ``@`` in the authority is
    userinfo. A port that is not a number is what a password holding an unencoded ``/``, ``?`` or
    ``#`` looks like: the authority stops there, no ``@`` is seen, and the password's head becomes the
    port. When that head is a number or empty the port passes, so an ``@`` after a port is refused
    too (BACKLOG #2686). An EMPTY port (``host:/``) with no ``@`` after it passes, because ``urlsplit``
    reads it as no port and ``http.client`` as the default. Not every shape is caught: an ``@`` with
    no port is ordinary path text, and the comment on the third check names another.

    ``proxy_url`` is deliberately NOT screened here: :func:`proxy_config_from_settings` has its own
    refusal, which reads the URL as urllib does, and #1207 masks a credential for display.

    PHI- and secret-safe: names the setting, never the URL or any part of it. ``error`` keeps each
    seam's own ``ValueError`` subclass, so a caller catching ``HttpAuthError`` still catches this."""
    p = _split_or_refuse(url, setting, use=use, error=error)
    if "@" in urllib.parse.unquote(p.netloc):
        raise error(
            f"{setting} must not carry credentials in the URL (the user:password@ part); "
            f"set them in {use} instead"
        )
    # Read as strings, never through ``p.port``: its ValueError quotes the port field, which is the
    # password in ``https://svc:PW/path`` (#1796).
    ports = _port_fields(p.netloc)
    if not all(_is_port(port) for port in ports):
        raise error(
            f"{setting} has a port that is not a number from 0 to 65535. A password written "
            f"into the URL can cause this; set credentials in {use} instead"
        )
    # A numeric password head passes the port check (BACKLOG #2686): ``svc:12/ss@host`` reads as
    # host ``svc``, port 12. Refused when an ``@`` follows the port in the path, or anywhere after
    # it when the path is empty (the ``?`` and ``#`` heads), or in a fragment, which is never sent.
    # An ``@`` in a query value after a real path still passes; so does any ``@`` with no port. That
    # leaves a password such as ``12/a?b`` constructible; ``_redact_url`` still withholds it.
    tail = p.path + (p.query if not p.path else "") + p.fragment
    if ports and "@" in tail:
        raise error(
            f"{setting} has a port followed by an '@'. A password written into the URL can cause "
            f"this; set credentials in {use} instead. Write a literal '@' as %40, or leave out a "
            "default port"
        )
    # A password head written with ``%3A`` and then ``%5D`` hides its port from both readers above,
    # since the dialling reader takes the ``]`` for an IPv6 literal's end (BACKLOG #2686). No host
    # name holds a ``:``, so an encoded one outside brackets is refused whatever follows it.
    if _host_holds_encoded_colon(p):
        raise error(
            f"{setting} has a ':' written as %3A in its host. A password written into the URL can "
            f"cause this; set credentials in {use} instead"
        )


def _split_or_refuse(
    url: str, setting: str, *, use: str, error: type[ValueError]
) -> urllib.parse.SplitResult:
    """``urlsplit(url)``, or a refusal that names ``setting`` and nothing of the URL.

    Raised after the handler ends: urlsplit's NFKC ValueError quotes the whole netloc, password and
    all, and ``from None`` would leave it on ``__context__`` (#1796).

    Split uncached (vault BACKLOG #5287). At least :func:`url_scheme` and
    :func:`refuse_url_credentials` call this on a URL that may hold a credential, and a cached split
    would make a refused password a key in urllib's process-wide cache. The uncached function is
    the same code, so it raises the same NFKC ValueError. This keeps only this split from adding
    the key: a reader that splits the same value cached first, such as the egress gate's query
    credential warning on an endpoint ``url``, still adds one."""
    try:
        parsed: urllib.parse.SplitResult | None = UNCACHED_URLSPLIT(url)
    except ValueError:
        parsed = None
    if parsed is None:
        raise error(
            f"{setting} is not a URL that can be parsed. A password written into the URL can "
            f"cause this; set credentials in {use} instead"
        )
    return parsed
