# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The intake context: what a source knows about who handed it one inbound body (vault BACKLOG #2607).

Before this, the generic :data:`~messagefoundry.transports.base.InboundHandler` took the body and
nothing else, so a stored message could not name the peer that sent it. A source that knows the peer
now builds an :class:`IntakeContext` and hands it over with the body through :func:`deliver`; the
runner's handler, marked with :func:`intake_handler`, takes both, and writes the context into the
message's metadata in the ingress transaction.

The mark keeps the plain one-argument handler working: :func:`deliver` passes the context only to a
handler that declared it takes one, as :func:`~messagefoundry.transports.receipt.receipt_handler`
declares a receipt handler, because a return or parameter annotation cannot be read reliably at run
time.

Everything here is socket or path metadata, never a byte of the body. A certificate subject can name
a person; the runner writes the context into the message's metadata cell, which the store encrypts
at rest when it has a key, as it does ``connection_event.reason``.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, cast

from messagefoundry.transports.admission import PeerInfo

__all__ = [
    "IntakeAuth",
    "IntakeContext",
    "deliver",
    "intake_handler",
    "peer_address",
    "socket_intake",
]


class IntakeAuth(StrEnum):
    """How the listener admitted the peer, on the TLS axis. ``source_ip_allowlist`` is recorded
    beside it, as :attr:`IntakeContext.address_listed`, because it combines with any of these."""

    #: Plaintext: no peer identity is established by the transport.
    NONE = "none"
    #: TLS with no client certificate requested, so the peer is not identified by one.
    TLS = "tls"
    #: TLS with a client certificate the listener required and verified against its CA file.
    MTLS = "mtls"
    #: As :attr:`MTLS`, and the certificate is on ``tls_client_subjects`` under its issuing CA.
    MTLS_SUBJECTS = "mtls_subjects"


@dataclass(frozen=True, slots=True)
class IntakeContext:
    """Who handed the engine one body, as the source saw it.

    A listen source fills the peer fields from the accepted socket; a poll source has no peer and
    fills :attr:`source` with where it read the body. A ``None`` field is left out of the stored
    record; what ``None`` means is on each field."""

    #: The source's transport, lower case, such as ``"mllp"``, ``"tcp"`` or ``"file"``.
    transport: str
    #: The peer's address as the accepted socket reports it.
    peer_host: str | None = None
    #: The peer's port, so two connections from one translated address are told apart.
    peer_port: int | None = None
    #: The local ``host:port`` of the socket that accepted the connection.
    listener: str | None = None
    #: The verified client certificate's subject, RFC 4514, when one was required and verified.
    cert_subject: str | None = None
    #: How the peer was admitted; ``None`` for a poll source, which admits no peer.
    auth_mode: IntakeAuth | None = None
    #: ``True`` when the inbound has a ``source_ip_allowlist`` and the peer was on it; ``None`` when
    #: the inbound has none, so the address was not screened.
    address_listed: bool | None = None
    #: A poll source's origin, such as the file path the File source read the body from.
    source: str | None = None

    def fields(self) -> dict[str, Any]:
        """The context as a JSON-ready mapping, with every unknown field left out."""
        return {
            f.name: value
            for f in dataclasses.fields(self)
            if (value := getattr(self, f.name)) is not None
        }


def peer_address(name: object) -> tuple[str | None, int | None]:
    """The host and port of a socket address as ``get_extra_info("peername")`` or ``"sockname"``
    reports it, or ``(None, None)`` for a shape that carries neither (a UNIX socket, say)."""
    if isinstance(name, tuple) and len(name) >= 2 and isinstance(name[0], str):
        port = name[1] if isinstance(name[1], int) and not isinstance(name[1], bool) else None
        return name[0], port
    return None, None


def _host_port(name: object) -> str | None:
    host, port = peer_address(name)
    if host is None or port is None:
        return None
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def socket_intake(
    peer: PeerInfo,
    *,
    transport: str,
    auth_mode: IntakeAuth,
    cert_subject: str | None = None,
    address_allowlist: bool = False,
) -> IntakeContext:
    """The intake context of one accepted socket connection, read once after it was admitted.

    ``auth_mode`` and ``cert_subject`` come from the listener, which knows its own TLS setup; this
    module reads no certificate. ``address_allowlist`` is ``True`` when the listener has a source
    address allowlist, which the peer passed to get here."""
    peer_host, peer_port = peer_address(peer.get_extra_info("peername"))
    return IntakeContext(
        transport=transport,
        peer_host=peer_host,
        peer_port=peer_port,
        listener=_host_port(peer.get_extra_info("sockname")),
        cert_subject=cert_subject,
        auth_mode=auth_mode,
        address_listed=True if address_allowlist else None,
    )


#: The attribute :func:`intake_handler` sets, which :func:`deliver` reads.
_INTAKE_MARK = "__messagefoundry_intake_handler__"


def intake_handler[H: Callable[..., Awaitable[object]]](handler: H) -> H:
    """Mark ``handler`` as taking ``(body, intake)``, so :func:`deliver` hands it the context.

    A marked handler must also accept the body alone, because a source that knows no peer still
    calls it with one argument."""
    setattr(handler, _INTAKE_MARK, True)
    return handler


async def deliver[R](
    handler: Callable[[bytes], Awaitable[R]], raw: bytes, intake: IntakeContext | None
) -> R:
    """Call ``handler`` with ``raw``, and with ``intake`` too when the handler is marked by
    :func:`intake_handler` and there is a context to give. An unmarked handler is called exactly
    as before, so a source passes its context without knowing which handler it was started with."""
    if intake is not None and getattr(handler, _INTAKE_MARK, False) is True:
        # The mark is the check the type system cannot make, as require_receipt's cast is.
        takes_intake = cast("Callable[[bytes, IntakeContext], Awaitable[R]]", handler)
        return await takes_intake(raw, intake)
    return await handler(raw)
