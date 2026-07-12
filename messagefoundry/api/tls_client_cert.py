# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Scope-populating shim that surfaces a VERIFIED mTLS peer certificate to the ASGI request (ADR 0083).

The deny-by-default resolver in :mod:`messagefoundry.api.security` maps a verified client certificate to
a MessageFoundry principal, but stock uvicorn builds the ASGI ``scope`` with only ``scheme`` — no
``transport``/``ssl_object`` and no ASGI-TLS extension — so the resolver is **inert** under the shipped
server. This module activates it with a **minimal HTTP-protocol subclass** whose ONLY behavioural change
is: after the TLS handshake completes, read the verified peer certificate (stdlib ``ssl``) and thread it
through to the request.

WHY ``connection_made`` + a per-connection ``app_state`` snapshot (and not ``scope['transport']``):
uvicorn assembles the scope inline inside a monolithic event handler with **no** post-build hook to
enrich, but it *does* copy ``self.app_state`` into ``scope['state']`` on every request. asyncio invokes
``connection_made`` on the wrapped protocol only **after** the SSL handshake finishes, so
``transport.get_extra_info('ssl_object').getpeercert()`` there returns the CERT_REQUIRED-verified peer
cert. Replacing *this protocol instance's* ``app_state`` reference with an enriched copy (we never mutate
the shared lifespan-state dict) threads the cert through cleanly, per-connection, without forking uvicorn
or reimplementing its request loop.

BYTE-IDENTICAL when no client cert is presented: ``getpeercert()`` returns ``{}`` on a plaintext or
server-only-TLS connection, so :func:`enriched_app_state` returns the state unchanged and nothing is
stashed. The serve path only swaps in this protocol when in-process mTLS **and** a cert-identity map are
both configured, so the loopback / no-mTLS path never even instantiates it.

We stash the raw ``getpeercert()`` dict (never the certificate PEM or any private material) so no secret
is placed in the ASGI state; :func:`messagefoundry.api.security.peer_cert_from_request` reads it back.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

__all__ = [
    "MF_CLIENT_PEERCERT_STATE_KEY",
    "client_cert_http_protocol_class",
    "enriched_app_state",
    "extract_verified_peercert",
]

# Private ASGI ``scope['state']`` key under which the shim stashes the verified peer cert. The leading
# underscore + package prefix keeps it clear of any application state and un-guessable as a spoof target
# (a client cannot set scope state — only this in-process shim does).
MF_CLIENT_PEERCERT_STATE_KEY = "_mf_client_peercert"


def extract_verified_peercert(transport: asyncio.BaseTransport) -> Mapping[str, Any] | None:
    """The verified peer certificate (``ssl.getpeercert()`` dict) for ``transport``, or ``None``.

    Returns ``None`` for a non-TLS transport, a TLS connection with no client cert (server-only TLS or a
    still-incomplete handshake), or any malformed transport. Only a socket built with
    ``ssl.CERT_REQUIRED`` (the in-process mTLS path, ``[api].tls_client_ca_file``) yields a non-empty
    dict here, so an unverified / self-signed cert never surfaces — deny-by-default is preserved
    upstream regardless."""
    get_extra_info = getattr(transport, "get_extra_info", None)
    if get_extra_info is None:
        return None
    ssl_object = get_extra_info("ssl_object")
    if ssl_object is None:
        return None  # plaintext transport — nothing to surface
    try:
        cert = ssl_object.getpeercert()
    except ValueError:
        return None  # handshake not complete — no verified cert yet
    # getpeercert() returns {} when the peer presented no cert; treat that as "no cert" so nothing is
    # stashed and the resolver denies rather than matching an empty subject.
    result: Mapping[str, Any] | None = cert or None
    return result


def enriched_app_state(
    app_state: Mapping[str, Any], transport: asyncio.BaseTransport
) -> Mapping[str, Any]:
    """``app_state`` unchanged, or a **per-connection copy** carrying the verified peer cert.

    Pure and side-effect-free: it never mutates ``app_state`` (that dict is the process-wide lifespan
    state shared by every connection), returning a fresh dict only when a client cert is actually
    present. So a connection with no client cert observes byte-identical state."""
    peercert = extract_verified_peercert(transport)
    if peercert is None:
        return app_state
    return {**app_state, MF_CLIENT_PEERCERT_STATE_KEY: peercert}


def client_cert_http_protocol_class(base: type[Any] | None = None) -> type[asyncio.Protocol]:
    """An HTTP-protocol subclass that stashes the verified peer cert into ``app_state`` post-handshake.

    ``base`` defaults to uvicorn's resolved ``AutoHTTPProtocol`` (httptools when installed, else h11);
    it is a parameter only so the override logic is unit-testable against a stub base without standing up
    uvicorn's real protocol. Pass the result as uvicorn's ``http=`` protocol class. The subclass adds
    nothing but the ``connection_made`` enrichment above — every other behaviour is inherited."""
    if base is None:
        # Imported lazily so importing this module does not pull uvicorn into non-serve contexts.
        from uvicorn.protocols.http.auto import AutoHTTPProtocol

        base = AutoHTTPProtocol

    # Dynamic base class (uvicorn types AutoHTTPProtocol as a `type[asyncio.Protocol]` *value*, which
    # mypy cannot use as a static base) — hence the localized ignore, not a blanket one.
    class _ClientCertHTTPProtocol(base):  # type: ignore[misc,valid-type]
        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            super().connection_made(transport)
            # self.app_state is uvicorn-internal (not on asyncio.Protocol); go through Any so the read +
            # per-connection replacement stay mypy-strict clean without weakening the module's typing.
            protocol: Any = self
            protocol.app_state = enriched_app_state(protocol.app_state, transport)

    return _ClientCertHTTPProtocol
