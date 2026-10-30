# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One reading of a forward-proxy URL, for the gate that judges it and the client that dials it
(vault BACKLOG #2965, ADR 0126).

Two parsers read a ``proxy_url``. ``[egress].allowed_proxy`` judged the host
``urllib.parse.urlsplit`` reads, and urllib's proxy handler dials the host its private
``_parse_proxy`` reads. The two do not agree on every value. ``urlsplit`` ends the authority at
the first ``/``, ``?`` or ``#``. ``_parse_proxy`` reads an ``@`` past that point as the end of a
userinfo, so a second host written after it is the one dialled. Such a value passed the allow-list
for one host while urllib dialled another, carrying any ``Proxy-Authorization`` the connection
sends.

So a configured proxy URL is parsed once, here, by :func:`parse_proxy_url`. It refuses a value
the two parsers could read differently, and gives back the parts the value is rebuilt from: the
scheme, an optional userinfo, the host and the port. The gate judges that host and port, the
connector dials the rebuilt URL, and the static-credential hop names that host. A refusal names
no part of the value, because the value may carry a credential.

:func:`read_like_urllib` is ``_parse_proxy`` itself, for the send-time readers that must read a
value exactly as the handler does, including a value from the operating system's proxy settings
that never passed through :func:`parse_proxy_url`. The gate, the connector build, the
static-credential hop label and at least the ``bounded_read`` send-time checks read through this
module. Other proxy-URL readers exist and do not, at least ``ambient_proxy``'s label and the
``requests``/``hvac`` path in ``strict_requests``.

``urlsplit`` is called here with its cache taken off, as ``strict_requests`` does (vault BACKLOG
#3454), so this parse adds no key to the process-wide cache. That is all it does: every caller
reads the scheme first through the cached function, so the value is a cache key all the same.

Imports only the standard library, so ``bounded_read`` and ``rest`` can both use it without a
cycle.
"""

from __future__ import annotations

import inspect
import ipaddress
import re
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field

__all__ = [
    "ProxyAddress",
    "parse_proxy_url",
    "read_like_urllib",
]

#: One DNS label: letters, digits and inner hyphens, at most 63 characters. The same label rule
#: as ``messagefoundry.domainshape``, restated because that rule refuses a dotted IPv4 address and
#: a trailing dot, which a proxy host may be written with.
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
#: A host name or a dotted IPv4 address, with an optional trailing dot. No percent-escape, no
#: underscore and no other character that a later reader could decode into something else.
_NAME_HOST = re.compile(rf"{_LABEL}(?:\.{_LABEL})*\.?")
#: A label a resolver's IPv4 shorthand reads as a number: decimal, octal or hex.
_NUMERIC_LABEL = re.compile(r"(?:0[xX][0-9A-Fa-f]*|[0-9]+)")
#: A port as digits only. Its range is checked apart, so ``0`` and ``99999`` read as refused.
_PORT = re.compile(r"[0-9]{1,5}")

#: ``urlsplit`` without its ``functools.lru_cache`` layer; the module docstring says why.
_UNCACHED_URLSPLIT: Callable[[str], urllib.parse.SplitResult] = inspect.unwrap(
    urllib.parse.urlsplit
)

#: The fixed refusal text. It names the setting and the rule, never the value.
_REFUSED = (
    "proxy_url must be http(s)://[user:password@]host[:port] with nothing after the port but an "
    "optional '/': no path, query or fragment, a host that is a DNS name, an IPv4 address or a "
    "bracketed IPv6 address, written in ASCII, and a port from 1 to 65535 with no leading zero. "
    "Percent-encode any '/', '?', '#' or '@' in the user or password, or set them in "
    "proxy_user/proxy_password (vault BACKLOG #2965)"
)


@dataclass(frozen=True, slots=True)
class ProxyAddress:
    """A proxy URL that both parsers read the same way, and the parts it is rebuilt from.

    ``host`` is as written, with an IPv6 address's brackets. ``userinfo`` is kept as written,
    percent-escapes included, because urllib unquotes it when it builds the header."""

    scheme: str
    host: str
    port: int | None
    userinfo: str | None = field(default=None, repr=False)

    @property
    def hostname(self) -> str:
        """What the allow-list matches: lower-cased, brackets removed, as ``urlsplit`` gives it."""
        return self.host.removeprefix("[").removesuffix("]").lower()

    @property
    def hostport(self) -> str:
        """``host[:port]``, which is what urllib's handler hands ``http.client`` to dial."""
        return self.host if self.port is None else f"{self.host}:{self.port}"

    @property
    def url(self) -> str:
        """The rebuilt URL the connector dials: userinfo included, no path, no trailing ``/``."""
        auth = f"{self.userinfo}@" if self.userinfo is not None else ""
        return f"{self.scheme}://{auth}{self.hostport}"

    @property
    def label_url(self) -> str:
        """The rebuilt URL without its userinfo, for a label or a log line."""
        return f"{self.scheme}://{self.hostport}"


def read_like_urllib(proxy: str) -> tuple[str | None, str | None, str | None, str]:
    """``(scheme, user, password, hostport)`` exactly as ``ProxyHandler.proxy_open`` reads
    ``proxy``. Raises urllib's own ``ValueError``, whose text quotes the value, so a caller must
    not let that text out. A test pins that this is the function the handler calls."""
    # Private, but it is exactly what ProxyHandler.proxy_open calls.
    parsed: tuple[str | None, str | None, str | None, str] = urllib.request._parse_proxy(proxy)  # type: ignore[attr-defined]
    return parsed


def _is_strict_host(host: str) -> bool:
    """Whether ``host`` is a DNS name, a dotted IPv4 address or a bracketed IPv6 address."""
    if host.startswith("["):
        inner = host[1:-1]
        # An IPv6 address only: no zone id, which urllib would unquote, and no IPvFuture form.
        if not host.endswith("]") or "%" in inner:
            return False
        try:
            ipaddress.IPv6Address(inner)
        except ValueError:
            return False
        return True
    if len(host) > 253 or _NAME_HOST.fullmatch(host) is None:
        return False
    # A host of numeric labels only is an IPv4 address to a resolver, which reads shorthand such as
    # a bare integer, an octal or hex label, or fewer than four parts as another address. So only
    # the canonical dotted quad is taken, and the text judged is the address dialled.
    if all(_NUMERIC_LABEL.fullmatch(label) for label in host.rstrip(".").split(".")):
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            return False
    return True


def parse_proxy_url(value: str) -> ProxyAddress:
    """Parse a configured ``http(s)`` proxy URL once, or raise ``ValueError`` with fixed text.

    Refused, at least: a value either parser cannot read; a scheme other than ``http`` or
    ``https``, or one not followed by ``://``; a path other than one bare ``/``; any ``?`` or
    ``#``; a host that is not an ASCII DNS name, a canonical dotted-quad IPv4 address or a
    bracketed IPv6 address with no zone; a port outside 1 to 65535 or written with a leading
    zero; and any value on which ``urlsplit`` and urllib's ``_parse_proxy`` read a different
    scheme, userinfo, host or port. The code below is the full rule; this list is a guide to it.
    A userinfo stays allowed. The caller strips the value and handles ``"default"``
    first. Neither the message nor the exception chain carries any part of the value."""
    try:
        parts = _UNCACHED_URLSPLIT(value)
        u_scheme, u_user, u_password, u_hostport = read_like_urllib(value)
    except ValueError:
        parts = None
    if parts is None:
        raise ValueError(_REFUSED)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not value[len(parts.scheme) :].startswith("://"):
        raise ValueError(_REFUSED)
    # '?' and '#' are refused anywhere, not only with text after them: urllib reads an empty
    # query or fragment into the host port, and urlsplit does not.
    if parts.path not in ("", "/") or "?" in value or "#" in value:
        raise ValueError(_REFUSED)
    userinfo, at, host_port = parts.netloc.rpartition("@")
    if host_port.startswith("["):
        host, _, rest = host_port.partition("]")
        host += "]"
        if rest and not rest.startswith(":"):
            raise ValueError(_REFUSED)
        port_text: str | None = rest[1:] if rest else None
    else:
        host, colon, port_text_raw = host_port.partition(":")
        port_text = port_text_raw if colon else None
    if not _is_strict_host(host):
        raise ValueError(_REFUSED)
    port: int | None = None
    if port_text is not None:
        if not _PORT.fullmatch(port_text) or not 1 <= int(port_text) <= 65535:
            raise ValueError(_REFUSED)
        port = int(port_text)
    address = ProxyAddress(
        scheme=scheme,
        host=host,
        port=port,
        userinfo=userinfo if at else None,
    )
    # The two readings must agree, on the value as written and on the URL rebuilt from it, which
    # is what is dialled. urllib unquotes the host port before it dials, so the unquoted form is
    # compared. The rebuilt URL keeps the netloc as written, so urlsplit is not run on it again.
    try:
        rebuilt: tuple[str | None, str | None, str | None, str] | None = read_like_urllib(
            address.url
        )
    except ValueError:
        rebuilt = None  # raised below, after the handler, so the chain holds no urllib text
    if (
        rebuilt is None
        or (u_scheme or "").lower() != scheme
        or (rebuilt[0] or "").lower() != scheme
        or urllib.parse.unquote(u_hostport) != address.hostport
        or urllib.parse.unquote(rebuilt[3]) != address.hostport
        or (u_user, u_password) != rebuilt[1:3]
        or (u_user, u_password) != (parts.username, parts.password)
        or parts.hostname != address.hostname
    ):
        raise ValueError(_REFUSED)
    return address
