# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Where the engine's API TLS material comes from, and where it mints its own (ADR 0172).

Stdlib-only, so :mod:`messagefoundry.api.tls` (which serves with the material),
:mod:`messagefoundry.tray` (which must verify it, and by ADR 0113 may not import ``api/`` or
``config/``) and :mod:`messagefoundry.config.settings` (``ApiSettings.serves_plaintext_upstream_hop``,
which imports it at module top level, so this module must never import ``config/``) share ONE copy
of the rule. Two copies had drifted before: keying the scheme on
``[api].tls_cert_file`` alone read the shipped default as cleartext (BACKLOG #1126).
"""

from __future__ import annotations

import ipaddress
from typing import Literal

#: Where the material the API bind serves with comes from. ``upstream`` is the one source that is not
#: material at all -- a declared reverse proxy terminates TLS in front and the engine serves plaintext.
ApiTlsSource = Literal["operator", "generated", "upstream"]

#: The filename the engine mints its self-signed API certificate to, beside the store database.
GENERATED_CERT_NAME = "api-generated-cert.pem"


def api_tls_source(*, cert_file: str | None, tls_terminated_upstream: bool) -> ApiTlsSource:
    """The ORDER: an operator chain wins, a declared upstream terminator mints nothing, else generated.

    Takes the two settings rather than an ``ApiSettings``, so a caller that cannot afford the
    settings machinery -- the tray reads an untrusted, possibly-malformed service TOML and must
    degrade rather than raise -- shares the ordering without sharing the machinery.
    """
    if cert_file:
        return "operator"
    return "upstream" if tls_terminated_upstream else "generated"


def wildcard_loopback(host: str) -> str | None:
    """The loopback a client on this box reaches a WILDCARD bind through, or ``None`` (BACKLOG #5973).

    A wildcard bind (``0.0.0.0``, ``::``, bracketed or not) listens on every address of its family,
    loopback included, but is not itself an address a client can connect to. ``::`` maps to ``::1``
    rather than ``127.0.0.1`` because asyncio's ``create_server``, which ``uvicorn.run`` reaches, sets
    ``IPV6_V6ONLY`` on an IPv6 listener. Any other host, a name included, is not a wildcard.

    ONE copy for two callers: the engine names this address in the certificate it mints for a
    wildcard bind (:mod:`messagefoundry.api.tls`), and the tray dials it
    (:mod:`messagefoundry.tray.config`), so the address dialled and the name verified are one rule.
    """
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None
    if not ip.is_unspecified:
        return None
    return "::1" if ip.version == 6 else "127.0.0.1"


def unbracketed(host: str) -> str:
    """``host`` without the brackets a URL puts round an IPv6 literal, so ``[::1]`` reads ``::1``.

    Only a bracketed IP literal loses them; any other host is returned as written. A certificate
    must name ``::1`` as an IP address, because hostname verification of ``https://[::1]`` compares
    the address, and a DNS name spelled ``[::1]`` matches no URL (BACKLOG #5973).
    """
    if host.startswith("[") and host.endswith("]"):
        try:
            ipaddress.ip_address(host[1:-1])
        except ValueError:
            return host
        return host[1:-1]
    return host


def dialled_host(host: str) -> str:
    """The host a client on this box dials for an API bind on ``host`` (BACKLOG #5973).

    The family's loopback for a wildcard (:func:`wildcard_loopback`), else ``host`` without IPv6
    brackets (:func:`unbracketed`). ONE copy: the tray dials it (:mod:`messagefoundry.tray.config`),
    and the engine re-mints a reused generated certificate that does not name it
    (:mod:`messagefoundry.api.tls`).
    """
    return wildcard_loopback(host) or unbracketed(host)
