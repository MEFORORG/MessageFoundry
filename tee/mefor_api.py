# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""MEFOR engine API client for the tee parity comparison (#14) — stdlib only.

Pulls MEFOR's transformed outbound payloads from the engine's localhost API for ``tee compare``:
``GET /messages`` (paginated) for the message list, then ``GET /messages/{id}/outbound`` (#354) for each
message's per-destination transformed payloads. Uses :mod:`urllib.request` deliberately — the tee stays
standalone (stdlib + ``aiosqlite``), the same dependency-minimal principle as the vendored MLLP/HL7
codecs: a few authenticated GETs to a default-localhost engine need only a timeout, a bearer-token
header and an optional TLS context. (mTLS / rich retry against a remote TLS engine would be the trigger
to revisit a richer HTTP client — deferred, not built.)

The ``/messages/{id}/outbound`` body is PHI; callers handle it under the test-data-only guardrail.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from ssl import SSLContext
from typing import Any
from urllib.parse import urlsplit

from tee.correlate import MeforOutput

#: A ``path -> parsed JSON`` getter (injectable, so the assembly logic is testable without HTTP).
JsonGetter = Callable[[str], dict[str, Any]]


class MeforApiError(RuntimeError):
    """A MEFOR API request failed (transport, auth, throttle, or a non-2xx status)."""


def _is_loopback_host(host: str | None) -> bool:
    """Whether ``host`` names this box, read from the URL alone with no DNS lookup (BACKLOG #2708).

    The engine's rule, copied because the tee imports no ``messagefoundry``: the name
    ``localhost``, or an address :mod:`ipaddress` calls loopback, so all of ``127.0.0.0/8`` and
    ``::1``. Any other name cannot be proven on-box without DNS, so it is not. A missing or empty
    host is not on-box either. The source is ``is_never_proxied_host`` in
    ``messagefoundry/transports/bounded_read.py``."""
    if not host:
        return False
    host = host.lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _LoopbackDirect(urllib.request.ProxyHandler):
    """urllib's proxy handler, except that a loopback engine is dialled direct (BACKLOG #2708).

    The stock handler sends ``http://127.0.0.1`` to ``HTTP_PROXY``, or to the system proxy, unless
    ``NO_PROXY`` names the host. That proxy would read the bearer token in clear. The engine's own
    openers dial a loopback host direct (``LoopbackDirectProxyHandler``); this copy keeps the tee on
    the standard library. An off-box engine still goes through a set proxy."""

    def proxy_open(self, req: urllib.request.Request, proxy: str, type: str) -> Any:  # noqa: A002
        try:
            host = urlsplit(req.full_url).hostname
        except ValueError:
            host = None  # a URL nobody can read a host from; urllib's own handling decides
        if _is_loopback_host(host):
            return None  # not rewritten, so the scheme's own handler dials the host itself
        return super().proxy_open(req, proxy, type)


def make_getter(
    base_url: str,
    token: str,
    *,
    timeout: float = 30.0,
    ssl_context: SSLContext | None = None,
) -> JsonGetter:
    """A ``path -> parsed JSON`` getter bound to ``base_url`` with a bearer token, timeout and optional
    TLS context. Raises :class:`MeforApiError` on any transport/HTTP error — a 429 anti-automation
    throttle is surfaced verbatim (narrow ``--since``/``--limit`` and re-run)."""
    base = base_url.rstrip("/")
    # A hand-built opener must be handed the context, or it uses the default trust store instead.
    opener = urllib.request.build_opener(
        _LoopbackDirect(), urllib.request.HTTPSHandler(context=ssl_context)
    )

    def get(path: str) -> dict[str, Any]:
        url = base + path
        req = urllib.request.Request(
            url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}
        )
        try:
            # `base_url` is operator config (default localhost), so the URL scheme is fixed by the
            # operator and never derived from message/HL7 content — B310's non-http(s)-scheme concern
            # does not apply (a few authenticated GETs to the local engine API).
            with opener.open(req, timeout=timeout) as resp:  # nosec B310
                payload = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise MeforApiError(f"GET {path} -> HTTP {exc.code} {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise MeforApiError(f"GET {path} failed: {exc.reason}") from exc
        try:
            result: dict[str, Any] = json.loads(payload)
        except ValueError as exc:
            raise MeforApiError(f"GET {path} -> invalid JSON: {exc}") from exc
        return result

    return get


def fetch_mefor_outputs(
    get: JsonGetter,
    *,
    since: float | None = None,
    limit: int = 500,
    page: int = 50,
) -> list[MeforOutput]:
    """Pull MEFOR transformed outbound payloads — one :class:`MeforOutput` per (message, destination).

    Pages ``GET /messages`` (scanning at most ``limit`` messages) and fetches ``GET
    /messages/{id}/outbound`` for each. ``since`` (epoch) drops messages received before it — a
    **client-side** window, since the list endpoint has no time filter. ``page`` is the page size."""
    outputs: list[MeforOutput] = []
    offset = 0
    scanned = 0
    while scanned < limit:
        data = get(f"/messages?limit={page}&offset={offset}")
        messages = data.get("messages", [])
        if not messages:
            break
        for message in messages:
            if scanned >= limit:
                break
            scanned += 1
            if since is not None and float(message.get("received_at", 0.0)) < since:
                continue
            mid = message.get("id")
            if not mid:
                continue
            control_id = message.get("control_id") or ""
            outbound = get(f"/messages/{mid}/outbound")
            for entry in outbound.get("payloads", []):
                outputs.append(
                    MeforOutput(
                        message_id=mid,
                        source_control_id=control_id,
                        destination_name=entry.get("destination_name", ""),
                        payload=entry.get("payload", ""),
                    )
                )
        if len(messages) < page:
            break
        offset += page
    return outputs
