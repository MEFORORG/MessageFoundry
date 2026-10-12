# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Disclose a web proxy the engine may pick up from its environment (BACKLOG #1125, ASVS 4.2.1).

The owner ruling of 2026-10-11 says a proxy no engine setting names must not attach silently, or
must be disclosed. ADR 0126 Amendment B kept the urllib openers reading the environment, so
``serve`` and ``supervise`` disclose it: one WARNING as each engine process starts.

**The warning is static, so it is true by construction.** It names each proxy entry that is set,
by a label that never carries a credential, and one fixed sentence naming hops that *may* read an
environment proxy. It does not say an entry is read: a lone ``all`` entry with no ``[vault]``
extra reaches no hop, and it is still named. It makes no claim about which hop uses which entry, what reaches the proxy, or
what the leg to it protects. Four review rounds found that every per-hop verdict a probe produced
could be wrong, so the per-hop facts live once, in ``docs/CONFIGURATION.md``, *``serve`` names an
environment proxy at start*, and the warning points there.
"""

from __future__ import annotations

import importlib.util
import logging
import urllib.request
from collections.abc import Mapping
from typing import Any

# Private to wiring, and imported the way config/static_credentials.py imports its sibling
# _peer_label: the one secret-safe address parser, so a proxy URL is read the same way everywhere.
from messagefoundry.config.wiring import _split_address

__all__ = ["ambient_proxy_warning", "environment_proxy_hosts", "warn_ambient_proxy"]

#: The ``getproxies()`` keys an engine HTTP hop can read: urllib reads a target's own scheme, and
#: requests reads that or ``all``. Any other key, such as ``ftp`` or ``socks``, is not disclosed.
_READ_KEYS = ("all", "http", "https")
_UNREADABLE = "an unreadable value"

_HOPS = (
    "HTTP-family connections (REST, SOAP, FHIR, fhir_lookup, DICOMweb) and their OAuth2 and SMART "
    "token requests where no explicit proxy_url applies",
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


#: Shared by the warning and its fallback, so one search finds both.
_OPENING = "a web proxy from the environment or the system proxy settings"


def _address_of(value: object) -> str:
    """One proxy URL as ``scheme://host:port``, or a fixed placeholder when it does not parse.

    Read by the peer-label parser the posture read-out uses for a proxy URL, so the two agree, and
    so its refusals apply here too: whitespace, a control character, or a ``%`` that could hide an
    encoded userinfo in the host all give the placeholder rather than an echo. Leading or trailing
    whitespace does too, though the parser strips it: urllib reads the raw value, so a clean label
    would name an address the hop does not dial. A value with no scheme is read as ``http`` by both
    libraries, so it is named that way."""
    if not isinstance(value, str):  # a system reader that hands back something else
        return _UNREADABLE
    parts = _split_address(value) if value == value.strip() else None
    if parts is None:
        return _UNREADABLE
    scheme, host, port = parts
    return f"{scheme or 'http'}://{host}" + (f":{port}" if port else "")


def _read_entries(found: Mapping[Any, object]) -> dict[str, object]:
    """The entries of ``found`` an engine HTTP hop can read, keyed in lower case, in key order.

    A key that is not text is skipped, since no hop can look it up, so one odd key cannot stop the
    rest being disclosed. An empty string or ``None`` is no entry: urllib skips it, and requests
    treats it as no proxy. A value of only whitespace is kept, because both libraries would try to
    use it, and is labelled unreadable. Any other value that is not text is kept and labelled
    unreadable too, with no truth test that could raise on it.

    Where two set keys differ only in case, the lower-case one wins: the sort puts ``HTTPS`` before
    ``https``, and the later entry replaces it. ``getproxies()`` has already folded the case, so
    this matters only for a mapping a caller passes in."""
    entries = [
        (key.lower(), key, value)
        for key, value in found.items()
        if isinstance(key, str)
        and key.lower() in _READ_KEYS
        and value is not None
        and not (isinstance(value, str) and not value)
    ]
    entries.sort(key=lambda entry: (entry[0], entry[1]))
    return {lowered: value for lowered, _, value in entries}


def _label(value: object) -> str:
    """:func:`_address_of`, with any failure on one value labelled unreadable, so it cannot stop
    the other entries being disclosed."""
    try:
        return _address_of(value)
    except Exception:  # noqa: BLE001 - one odd value must not hide the rest
        return _UNREADABLE


def environment_proxy_hosts(proxies: Mapping[Any, object] | None = None) -> dict[str, str]:
    """The ``http``, ``https`` and ``all`` proxies from the environment or the system settings,
    each as ``scheme://host:port``. ``proxies`` defaults to ``urllib.request.getproxies()``."""
    found = urllib.request.getproxies() if proxies is None else proxies
    return {key: _label(value) for key, value in _read_entries(found).items()}


def _vault_importable() -> bool:
    """Whether the Vault clients could run at all: they need the ``[vault]`` extra's ``hvac``.

    Any failure of the lookup reads as no: the Vault clients are then left out, and the rest of
    the disclosure still logs."""
    try:
        return importlib.util.find_spec("hvac") is not None
    except Exception:  # noqa: BLE001 - a broken finder or sys.modules entry must not hide the rest
        return False


def _hops_sentence() -> str:
    """The fixed hop sentence. It reads no proxy value, so the fallback can carry it too."""
    hops = [*_HOPS, _VAULT] if _vault_importable() else list(_HOPS)
    return (
        "The hops that may read an environment proxy include at least "
        + ", ".join(hops[:-1])
        + f", and {hops[-1]}. "
    )


def ambient_proxy_warning(proxies: Mapping[Any, object] | None = None) -> str | None:
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
    return (
        f"{_OPENING} is set. " + lines + _hops_sentence() + _POINTER + _REMEDY + "(BACKLOG #1125)"
    )


def warn_ambient_proxy(logger: logging.Logger) -> None:
    """Log :func:`ambient_proxy_warning` at WARNING if there is one. Never raises.

    The disclosure must not stop an engine from starting, and a proxy must not attach silently. So
    a failure to build it still logs one WARNING, with the hop sentence, the pointer and the
    remedy. It carries no value, because the values it failed on may hold a proxy credential, and
    names only the exception's class. The fixed text goes in as arguments, so a ``%`` in it can
    never break the format."""
    try:
        text = ambient_proxy_warning()
    except Exception as exc:  # noqa: BLE001 - a startup disclosure must never stop serve or supervise
        logger.warning(
            "%s may be set; the disclosure could not be built (%s). %s%s%s(BACKLOG #1125)",
            _OPENING,
            type(exc).__name__,
            _hops_sentence(),  # cannot raise: _vault_importable catches every failure
            _POINTER,
            _REMEDY,
        )
        return
    if text is not None:
        logger.warning("%s", text)
