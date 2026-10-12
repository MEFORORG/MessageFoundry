# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Disclose a web proxy the engine picks up from its environment (BACKLOG #1125, ASVS 4.2.1).

The owner ruling of 2026-10-11 says a proxy no engine setting names must not attach silently, or
must be disclosed. ADR 0126 Amendment B kept the urllib openers reading the environment, so
``serve`` and ``supervise`` disclose it: one WARNING as each engine process starts. It names each
proxy's address, never a credential, and which hops use it or refuse it.

**The warning discloses; it does not reason about what the leg to the proxy protects.** Which
hops get a TLS leg, and what they send the proxy, depends on the whole proxy set. That is stated
once, in ``docs/CONFIGURATION.md``, *``serve`` names an environment proxy at start*, and the
warning points there.

**Which hops use each proxy is asked of the code that decides it, not kept in a table here.** A
request to a reserved host is run through the engine's own urllib proxy handler, and stopped
before anything is sent. The Vault decision is asked of ``requests``' own proxy selection and the
Vault clients' own refusal. Both read the same ``urllib.request.getproxies()`` this module reads.
"""

from __future__ import annotations

import importlib.util
import logging
import urllib.error
import urllib.request
from collections.abc import Iterator, Mapping
from typing import Any

# Private to wiring, and imported the way config/static_credentials.py imports its sibling
# _peer_label: the one secret-safe address parser, so a proxy URL is read the same way everywhere.
from messagefoundry.config.wiring import _split_address
from messagefoundry.transports.bounded_read import LoopbackDirectProxyHandler

__all__ = ["ambient_proxy_warning", "environment_proxy_hosts", "warn_ambient_proxy"]

#: The ``getproxies()`` keys an engine HTTP hop can read: urllib reads a target's own scheme, and
#: requests reads that or ``all``. Any other key, such as ``ftp`` or ``socks``, is not disclosed.
_READ_KEYS = ("all", "http", "https")
#: A reserved name (RFC 6761), so a probe that somehow got past its stop could dial nothing.
_PROBE_HOST = "ambient-proxy-probe.invalid"
_TARGET_SCHEMES = ("http", "https")

_URLLIB = "the urllib hops"
_VAULT = "the Vault and OpenBao clients"
_URLLIB_DEFINED = (
    "The urllib hops are HTTP-family connections (REST/SOAP/FHIR/fhir_lookup/DICOMweb) and their "
    "OAuth2 and SMART token requests wherever no explicit proxy_url applies to the host, the alert "
    "webhook, the OIDC sign-in requests and the AI broker. "
)
_POINTER = (
    "Which hosts go direct, and what each hop sends the proxy, is in docs/CONFIGURATION.md, "
    '[egress], "serve names an environment proxy at start". '
)
_REMEDY = (
    "To stop it, clear http_proxy, https_proxy and all_proxy in either case, and the system "
    "proxy, for the account the engine runs as. Setting [egress].proxy_url to an address changes "
    "only the HTTP-family connections and their token requests. Every other hop keeps this proxy, "
    "and this warning still logs, because it reads only the environment. "
)


def _address_of(value: str) -> str:
    """One proxy URL as ``scheme://host:port``, or a fixed placeholder when it does not parse.

    Read by the peer-label parser the posture read-out uses for a proxy URL, so the two agree, and
    so its refusals apply here too: whitespace, a control character, or a ``%`` that could hide an
    encoded userinfo in the host all give the placeholder rather than an echo. A value with no
    scheme is read as ``http`` by both libraries, so it is named that way."""
    parts = _split_address(value)
    if parts is None:
        return "an unreadable value"
    scheme, host, port = parts
    return f"{scheme or 'http'}://{host}" + (f":{port}" if port else "")


def _read_entries(found: Mapping[str, str]) -> dict[str, str]:
    """The entries of ``found`` an engine HTTP hop can read, keyed in lower case, in key order."""
    return {
        scheme.lower(): value
        for scheme, value in sorted(found.items())
        if scheme.lower() in _READ_KEYS and value.strip()
    }


def environment_proxy_hosts(proxies: Mapping[str, str] | None = None) -> dict[str, str]:
    """The ``http``, ``https`` and ``all`` proxies from the environment or the system settings,
    each as ``scheme://host:port``. ``proxies`` defaults to ``urllib.request.getproxies()``."""
    found = urllib.request.getproxies() if proxies is None else proxies
    return {key: _address_of(value) for key, value in _read_entries(found).items()}


class _RouteProbe(LoopbackDirectProxyHandler):
    """The engine's own urllib proxy handler, recording which entries a request goes through.

    ``reached`` holds each entry key the handler re-addressed the request to. urllib can chain two:
    an ``http`` target whose proxy is written ``https://`` is re-sent through the ``https`` entry.
    ``refused_by`` is the key of the innermost entry that raised, or ``None``."""

    def __init__(self, proxies: dict[str, str]) -> None:
        super().__init__(proxies)
        self.reached: set[str] = set()
        self.refused_by: str | None = None

    def proxy_open(self, req: urllib.request.Request, proxy: str, type: str) -> Any:  # noqa: A002
        before = req.host
        try:
            return super().proxy_open(req, proxy, type)
        except (urllib.error.URLError, ValueError):
            if self.refused_by is None:
                self.refused_by = type
            raise
        finally:
            if req.host != before:
                self.reached.add(type)


class _NoSend(urllib.request.BaseHandler):
    """Ends the probe where a strict handler would open the connection, so nothing is dialled."""

    def http_open(self, req: urllib.request.Request) -> urllib.request.Request:
        return req

    https_open = http_open


def _urllib_findings(entries: dict[str, str]) -> Iterator[tuple[str, str, str, bool]]:
    """``(entry key, family, target scheme, refused)`` for each entry a urllib target reaches."""
    for target in _TARGET_SCHEMES:
        probe = _RouteProbe(entries)
        opener = urllib.request.OpenerDirector()
        opener.add_handler(probe)
        opener.add_handler(_NoSend())
        url = f"{target}://{_PROBE_HOST}/"  # a URL, not a path: built apart from open()
        try:
            opener.open(url)
        except (urllib.error.URLError, ValueError):
            refused = True
        else:
            refused = False
        keys = probe.reached | ({probe.refused_by} if probe.refused_by else set())
        for key in sorted(keys):
            yield key, _URLLIB, target, refused


def _vault_findings(entries: dict[str, str]) -> Iterator[tuple[str, str, str, bool]]:
    """``(entry key, family, Vault scheme, refused)`` for each Vault scheme requests would proxy.

    None without the ``[vault]`` extra, which the Vault clients need to run at all."""
    if importlib.util.find_spec("hvac") is None:
        return
    try:
        import requests
        import requests.utils

        from messagefoundry.transports.strict_requests import _refuse_an_insecure_vault_hop
    except ImportError:
        return
    with requests.Session() as session:
        session.trust_env = False  # read ``entries``, the proxies the warning names
        for scheme in _TARGET_SCHEMES:
            url = f"{scheme}://{_PROBE_HOST}/"
            # requests' own selection, run on a map of each key to itself to learn which key wins.
            key = requests.utils.select_proxy(url, {k: k for k in entries})
            if key is None:
                continue
            try:
                # The refusal the Vault clients run at construction, in the order they run it. It
                # raises InsecureHopRefused, a ValueError; a parser's own ValueError also stops a
                # client being built, so both count as a refusal.
                _refuse_an_insecure_vault_hop(
                    session, url, connector="probe", request_proxies=dict(entries)
                )
            except ValueError:
                refused = True
            else:
                refused = False
            yield key, _VAULT, scheme, refused


def _targets(family: str, schemes: list[str]) -> str:
    if family == _VAULT:
        return "an " + " or ".join(f"{s}://" for s in schemes) + " Vault"
    return " and ".join(schemes) + " targets"


def _clauses(findings: list[tuple[str, str, bool]]) -> str:
    """One entry's findings as ``<family> use it for ... and refuse it for ...``, urllib first."""
    out = []
    for family in (_URLLIB, _VAULT):
        used = [t for f, t, r in findings if f == family and not r]
        refused = [t for f, t, r in findings if f == family and r]
        parts = [
            f"{verb} it for {_targets(family, ts)}"
            for verb, ts in (("use", used), ("refuse", refused))
            if ts
        ]
        if parts:
            out.append(f"{family} " + " and ".join(parts))
    return "; ".join(out) or "no engine hop reads it"


def ambient_proxy_warning(proxies: Mapping[str, str] | None = None) -> str | None:
    """The startup warning for an environment proxy, or ``None`` when there is none to disclose.

    ``proxies`` defaults to ``urllib.request.getproxies()``. A ``NO_PROXY`` of exactly ``*`` sends
    every hop direct in both client libraries, so there is then nothing to disclose. The value is
    compared unstripped, as urllib compares it, so a padded ``*`` that bypasses nothing still warns.
    """
    found = urllib.request.getproxies() if proxies is None else proxies
    if found.get("no") == "*":
        return None
    entries = _read_entries(found)
    if not entries:
        return None
    findings = [*_urllib_findings(entries), *_vault_findings(entries)]
    lines = [
        f"The {key} proxy is {_address_of(value)}: "
        + _clauses([(f, t, r) for k, f, t, r in findings if k == key])
        + ". "
        for key, value in entries.items()
    ]
    return (
        "a web proxy from the environment or the system proxy settings is in force, and no engine "
        "setting names it. "
        + "".join(lines)
        + (_URLLIB_DEFINED if any(f == _URLLIB for _, f, _, _ in findings) else "")
        + _POINTER
        + _REMEDY
        + "(BACKLOG #1125)"
    )


def warn_ambient_proxy(logger: logging.Logger) -> None:
    """Log :func:`ambient_proxy_warning` at WARNING if there is one."""
    text = ambient_proxy_warning()
    if text is not None:
        logger.warning("%s", text)
