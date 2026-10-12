# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Disclose a web proxy the engine may pick up from its environment (BACKLOG #1125, ASVS 4.2.1).

The owner ruling of 2026-10-11 says a proxy no engine setting names must not attach silently, or
must be disclosed. ADR 0126 Amendment B kept the urllib openers reading the environment, so
``serve`` and ``supervise`` disclose it: one WARNING as each engine process starts.

**The warning is static, so it is true by construction.** It names each proxy entry in force, by
a label that never carries a credential, and one fixed sentence naming hops that *may* read an
environment proxy. It makes no claim about which hop uses which entry, what reaches the proxy, or
what the leg to it protects. Four review rounds found that every per-hop verdict a probe produced
could be wrong, so the per-hop facts live once, in ``docs/CONFIGURATION.md``, *``serve`` names an
environment proxy at start*, and the warning points there.
"""

from __future__ import annotations

import importlib.util
import logging
import urllib.request
from collections.abc import Mapping

# Private to wiring, and imported the way config/static_credentials.py imports its sibling
# _peer_label: the one secret-safe address parser, so a proxy URL is read the same way everywhere.
from messagefoundry.config.wiring import _split_address

__all__ = ["ambient_proxy_warning", "environment_proxy_hosts", "warn_ambient_proxy"]

#: The ``getproxies()`` keys an engine HTTP hop can read: urllib reads a target's own scheme, and
#: requests reads that or ``all``. Any other key, such as ``ftp`` or ``socks``, is not disclosed.
_READ_KEYS = ("all", "http", "https")
_UNREADABLE = "an unreadable value"

_HOPS = (
    "HTTP-family connections (REST, SOAP, FHIR, fhir_lookup, DICOMweb) where no explicit "
    "proxy_url applies",
    "their OAuth2 and SMART token requests",
    "the alert webhook",
    "the OIDC sign-in and JWKS reads",
    "the AI broker",
)
#: Named only when ``hvac`` is importable: without the ``[vault]`` extra these clients cannot run.
_VAULT = "the Vault and OpenBao clients"
_POINTER = (
    "Per-hop detail, including which hosts go direct, is in docs/CONFIGURATION.md, [egress], "
    '"serve names an environment proxy at start". '
)
_REMEDY = (
    "To stop it, clear http_proxy, https_proxy and all_proxy in either case, and the system "
    "proxy, for the account the engine runs as. Setting [egress].proxy_url to an address changes "
    "only the HTTP-family connections and their token requests. Every other hop is unchanged, "
    "and this warning still logs, since it reads only the environment. "
)


def _address_of(value: str) -> str:
    """One proxy URL as ``scheme://host:port``, or a fixed placeholder when it does not parse.

    Read by the peer-label parser the posture read-out uses for a proxy URL, so the two agree, and
    so its refusals apply here too: whitespace, a control character, or a ``%`` that could hide an
    encoded userinfo in the host all give the placeholder rather than an echo. A value with no
    scheme is read as ``http`` by both libraries, so it is named that way."""
    parts = _split_address(value)
    if parts is None:
        return _UNREADABLE
    scheme, host, port = parts
    return f"{scheme or 'http'}://{host}" + (f":{port}" if port else "")


def _read_entries(found: Mapping[str, str]) -> dict[str, str]:
    """The entries of ``found`` an engine HTTP hop can read, keyed in lower case, in key order.

    An empty value is no entry: urllib skips it, and requests treats it as no proxy. A value of
    only whitespace is kept, because both libraries would try to use it, and is labelled
    unreadable."""
    return {
        scheme.lower(): value
        for scheme, value in sorted(found.items())
        if scheme.lower() in _READ_KEYS and value
    }


def environment_proxy_hosts(proxies: Mapping[str, str] | None = None) -> dict[str, str]:
    """The ``http``, ``https`` and ``all`` proxies from the environment or the system settings,
    each as ``scheme://host:port``. ``proxies`` defaults to ``urllib.request.getproxies()``."""
    found = urllib.request.getproxies() if proxies is None else proxies
    return {key: _address_of(value) for key, value in _read_entries(found).items()}


def _vault_importable() -> bool:
    """Whether the Vault clients could run at all: they need the ``[vault]`` extra's ``hvac``."""
    try:
        return importlib.util.find_spec("hvac") is not None
    except (ImportError, ValueError):  # a broken entry in sys.modules, or a parent that fails
        return False


def ambient_proxy_warning(proxies: Mapping[str, str] | None = None) -> str | None:
    """The startup warning for an environment proxy, or ``None`` when there is none to disclose.

    ``proxies`` defaults to ``urllib.request.getproxies()``. A ``NO_PROXY`` of exactly ``*`` sends
    every hop direct in both client libraries, so there is then nothing to disclose. The value is
    compared unstripped, as urllib compares it, so a padded ``*`` still warns. No other bypass
    entry is evaluated: whether it covers a hop depends on the host, which this cannot know.
    """
    found = urllib.request.getproxies() if proxies is None else proxies
    if found.get("no") == "*":
        return None
    hosts = environment_proxy_hosts(found)
    if not hosts:
        return None
    lines = "".join(f"The {key} proxy is {address}. " for key, address in hosts.items())
    hops = [*_HOPS, _VAULT] if _vault_importable() else list(_HOPS)
    return (
        "a web proxy from the environment or the system proxy settings is in force. "
        + lines
        + "The hops that may read an environment proxy include at least "
        + ", ".join(hops[:-1])
        + f", and {hops[-1]}. "
        + _POINTER
        + _REMEDY
        + "(BACKLOG #1125)"
    )


def warn_ambient_proxy(logger: logging.Logger) -> None:
    """Log :func:`ambient_proxy_warning` at WARNING if there is one. Never raises.

    The disclosure must not stop an engine from starting. A failure to build it logs one DEBUG
    line carrying no value, because the values it failed on may hold a proxy credential."""
    try:
        text = ambient_proxy_warning()
    except Exception:  # noqa: BLE001 - a startup disclosure must never stop serve or supervise
        logger.debug("the ambient proxy disclosure could not be built (BACKLOG #1125)")
        return
    if text is not None:
        logger.warning("%s", text)
