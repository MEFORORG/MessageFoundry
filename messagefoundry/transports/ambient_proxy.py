# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Disclose a web proxy the engine picks up from its environment (BACKLOG #1125, ASVS 4.2.1).

The owner ruling of 2026-10-11 says a proxy no engine setting names must not attach silently, or
must be disclosed. ADR 0126 Amendment B kept the urllib openers reading the environment, so
``serve`` and ``supervise`` disclose it: one WARNING as each engine process starts, naming each
proxy's address, never a credential, and at least the hops that follow it. Which hops, and why, is
in ``docs/CONFIGURATION.md``, *``serve`` names an environment proxy at start*, and ADR 0126
Amendment C.

urllib (``bounded_read.build_strict_opener``) and requests (``strict_requests``, the Vault clients)
both read the proxy through ``urllib.request.getproxies()``, so this reads the same call.
"""

from __future__ import annotations

import logging
import urllib.request
from collections.abc import Mapping

# Private to wiring, and imported the way config/static_credentials.py imports its sibling
# _peer_label: the one secret-safe address parser, so a proxy URL is read the same way everywhere.
from messagefoundry.config.wiring import _split_address

__all__ = ["ambient_proxy_warning", "environment_proxy_hosts", "warn_ambient_proxy"]

#: The ``getproxies()`` keys urllib's proxy handler reads for an http or https URL.
_URLLIB_SCHEMES = frozenset({"http", "https"})
#: The keys requests reads as well (``requests.utils.select_proxy``). Any other key, such as
#: ``ftp`` or ``socks``, reaches no engine HTTP hop, so it is not disclosed.
_HTTP_SCHEMES = _URLLIB_SCHEMES | {"all"}

#: The HTTP family reads the environment wherever no explicit ``proxy_url`` applies to the host:
#: no proxy set, ``proxy_url = "default"``, or a host its ``proxy_no_proxy`` bypasses.
_HTTP_FAMILY_HOPS = (
    "HTTP-family connections (REST/SOAP/FHIR/fhir_lookup/DICOMweb) and their OAuth2 and SMART "
    "token requests, wherever no explicit proxy_url applies to the host"
)
#: The urllib hops with no proxy setting of their own.
_OTHER_URLLIB_HOPS = ("the alert webhook", "the OIDC sign-in requests", "the AI broker")
#: The keys requests selects for an ``https://`` Vault. It honours ``all`` too, which urllib's
#: handler does not read.
_VAULT_SCHEMES = frozenset({"https", "all"})
#: The keys requests selects for an ``http://`` Vault. ``strict_requests`` refuses that hop behind
#: any proxy, loopback included, so such an entry carries no Vault hop but can break one.
_VAULT_REFUSING_SCHEMES = frozenset({"http", "all"})
#: requests has no loopback-direct rule, so an ``https://`` Vault on a loopback address is proxied.
_VAULT_HOPS = "the Vault and OpenBao clients, loopback addresses included"

_URLLIB_DIRECT = (
    "The urllib hops dial a loopback host direct, and a host on NO_PROXY or the system bypass "
    "list goes direct. A proxy URL that carries credentials and is not https:// is refused on "
    "each request. "
)
#: The proxy's scheme is not a TLS leg for the urllib hops, so the warning must not let it read
#: as one (SDS-3.7). ``bounded_read.ProxyCredentialsRefusedError`` holds the measurement: only an
#: ``http`` target, with no ``https`` proxy set, gets TLS to a proxy written ``https://``.
_URLLIB_NO_TLS_LEG = (
    "An https:// one is not refused, and is not safe either. With an https proxy set, the "
    "urllib hops reach every proxy over plain TCP, even one written https://. For an https "
    "target they send CONNECT, and any credential from the proxy URL, in cleartext. "
)
_URLLIB_HTTP_ONLY_LEG = (
    "With no https proxy set, an https target goes direct, and only an http proxy written "
    "https:// gets a TLS leg. "
)
#: What the Vault clients get that the urllib hops do not (``strict_requests``, BACKLOG #300).
_VAULT_TLS_LEG = "The Vault and OpenBao clients do open TLS to an https:// proxy. "
_VAULT_REFUSED = (
    "The Vault and OpenBao clients refuse an http:// Vault address that an http or all proxy "
    "would carry, loopback included. "
)
_REMEDY = (
    "To stop it, clear http_proxy, https_proxy and all_proxy in either case, and the system "
    "proxy, for the account the engine runs as. "
)
_PROXY_URL_REMEDY = (
    "Setting [egress].proxy_url to an address names a proxy for the HTTP family only. The other "
    "hops keep this proxy, and this warning still logs, because it reads only the environment. "
)


def _address_of(value: str) -> str:
    """One proxy URL as ``scheme://host:port``, or a fixed placeholder when it does not parse.

    Read by the peer-label parser the posture read-out uses for a proxy URL, so the two agree, and
    so its refusals apply here too: whitespace, a control character, or a ``%`` that could hide an
    encoded userinfo in the host all give the placeholder rather than an echo. A value with no
    scheme is read as ``http`` by both libraries, so it is named that way. The scheme is not always
    a TLS leg to the proxy; :data:`_URLLIB_NO_TLS_LEG` says when it is not."""
    parts = _split_address(value)
    if parts is None:
        return "an unreadable value"
    scheme, host, port = parts
    return f"{scheme or 'http'}://{host}" + (f":{port}" if port else "")


def environment_proxy_hosts(proxies: Mapping[str, str] | None = None) -> dict[str, str]:
    """The ``http``, ``https`` and ``all`` proxies from the environment or the system settings,
    each as ``scheme://host:port``. ``proxies`` defaults to ``urllib.request.getproxies()``."""
    found = urllib.request.getproxies() if proxies is None else proxies
    return {
        scheme.lower(): _address_of(value)
        for scheme, value in sorted(found.items())
        if scheme.lower() in _HTTP_SCHEMES and value.strip()
    }


def ambient_proxy_warning(proxies: Mapping[str, str] | None = None) -> str | None:
    """The startup warning for an environment proxy, or ``None`` when there is none to disclose.

    ``proxies`` defaults to ``urllib.request.getproxies()``. A ``NO_PROXY`` of exactly ``*`` sends
    every hop direct in both client libraries, so there is then nothing to disclose. The value is
    compared unstripped, as urllib compares it, so a padded ``*`` that bypasses nothing still warns.
    """
    found = urllib.request.getproxies() if proxies is None else proxies
    if found.get("no") == "*":
        return None
    hosts = environment_proxy_hosts(found)
    if not hosts:
        return None
    keys = hosts.keys()
    urllib_hops = bool(_URLLIB_SCHEMES & keys)
    vault_hops = bool(_VAULT_SCHEMES & keys)
    hops = [_HTTP_FAMILY_HOPS, *_OTHER_URLLIB_HOPS] if urllib_hops else []
    if vault_hops:
        hops.append(_VAULT_HOPS)
    parts = [
        "a web proxy from the environment or the system proxy settings is in force ("
        + "; ".join(f"{scheme} targets via {address}" for scheme, address in hosts.items())
        + "). At least these engine hops follow it for targets of a matching scheme, with no "
        f"engine setting naming it: {'; '.join(hops)}. "
    ]
    if urllib_hops:
        parts += [_URLLIB_DIRECT, _URLLIB_NO_TLS_LEG if "https" in keys else _URLLIB_HTTP_ONLY_LEG]
    if vault_hops:
        parts.append(_VAULT_TLS_LEG)
    if _VAULT_REFUSING_SCHEMES & keys:
        parts.append(_VAULT_REFUSED)
    parts.append(_REMEDY)
    if urllib_hops:
        parts.append(_PROXY_URL_REMEDY)
    return "".join(parts) + "(BACKLOG #1125)"


def warn_ambient_proxy(logger: logging.Logger) -> None:
    """Log :func:`ambient_proxy_warning` at WARNING if there is one."""
    text = ambient_proxy_warning()
    if text is not None:
        logger.warning("%s", text)
