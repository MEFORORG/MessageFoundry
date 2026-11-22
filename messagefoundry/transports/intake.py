# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The intake context: what a source knows about who handed it one inbound body (vault BACKLOG #2607).

Before this, the generic :data:`~messagefoundry.transports.base.InboundHandler` took the body and
nothing else, so a stored message could not name the peer that sent it. The MLLP and raw-TCP
listeners and the File source now build an :class:`IntakeContext` and hand it over with the body
through :func:`deliver`; other sources still pass the body alone. The
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

__all__ = [
    "IntakeAuth",
    "IntakeContext",
    "deliver",
    "intake_handler",
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

    It holds no socket address, neither the peer's nor the engine's own, by the owner's ruling of
    2026-11-22 ("No IP in metadata"). A value it records verbatim can still contain an IP, and
    nothing filters one out: at least a certificate subject such as ``CN=10.20.30.40``, and a
    File path under a UNC directory spelled by IP. The connection-event log,
    where capture is on, is where a peer address is kept, under
    ``[retention].connection_event_retention_hours``, and the message row's ``channel_id`` names
    the inbound connection that took it. A listen source fills how it admitted the peer; a poll
    source has no peer and fills :attr:`source` with where it read the body. A
    ``None`` field is left out of the stored record; what ``None`` means is on each field."""

    #: The source's transport, lower case, such as ``"mllp"``, ``"tcp"`` or ``"file"``.
    transport: str
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
