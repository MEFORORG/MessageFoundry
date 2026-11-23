# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The intake context: what a source knows about who handed it one inbound body (vault BACKLOG #2607).

Before this, the generic :data:`~messagefoundry.transports.base.InboundHandler` took the body and
nothing else, so a stored message could not name the peer that sent it. The MLLP and raw-TCP
listeners and the File source now build an :class:`IntakeContext` and hand it over with the body
through :func:`deliver`; other sources still pass the body alone. The
runner's handler, wrapped by :func:`intake_handler`, takes both, and writes the context into the
message's metadata in the ingress transaction.

:func:`deliver` keeps the plain one-argument handler working: it passes the context only to an
:class:`IntakeHandler`, which it recognises by class.

Everything here is connection or path metadata, never a byte of the body. A certificate subject can name
a person; the runner writes the context into the message's metadata cell, which the store encrypts
at rest when it has a key, as it does ``connection_event.reason``.
"""

from __future__ import annotations

import dataclasses
import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

__all__ = [
    "IntakeAuth",
    "IntakeContext",
    "IntakeHandler",
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
    File path under a UNC directory spelled by IP. A peer address is recorded elsewhere, at least
    in the connection-event log where capture is on and in some service-log lines; the message
    row's ``channel_id`` names the inbound connection that took it. The MLLP and raw-TCP listeners
    fill how they admitted the peer; the File source has no peer and fills :attr:`source` with
    where it read the body. A
    ``None`` field is left out of the stored record; what ``None`` means is on each field."""

    #: The source's transport, lower case, such as ``"mllp"``, ``"tcp"`` or ``"file"``.
    transport: str
    #: The verified client certificate's subject, RFC 4514, when one was required and verified;
    #: read once per connection, after the handshake. A renegotiation that presents another
    #: certificate is not re-read; OpenSSL 3 refuses a client-initiated one by default (measured on
    #: 3.5.7), and a listener with ``tls_client_subjects`` also sets ``OP_NO_RENEGOTIATION``.
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


class IntakeHandler[R]:
    """A handler that takes ``(body, intake=...)``: the runner's, wrapped by :func:`intake_handler`.

    :func:`deliver` recognises it by its class, not by an attribute, so a ``functools.wraps``
    wrapper around it, which copies attributes but not the class, is not mistaken for one and is
    called with the body alone. Building one checks the wrapped function takes an optional
    ``intake`` keyword, so a handler that cannot take the context fails when it is wrapped, not on
    the first message."""

    __slots__ = ("_handler",)

    def __init__(self, handler: Callable[..., Awaitable[R]]) -> None:
        param = inspect.signature(handler, follow_wrapped=False).parameters.get("intake")
        if (
            param is None
            or param.kind not in (param.POSITIONAL_OR_KEYWORD, param.KEYWORD_ONLY)
            or param.default is param.empty
        ):
            raise TypeError(
                "an intake handler must take an optional intake= keyword beside the body"
            )
        self._handler = handler

    async def __call__(self, raw: bytes, intake: IntakeContext | None = None) -> R:
        return await self._handler(raw, intake=intake)


def intake_handler[R](handler: Callable[..., Awaitable[R]]) -> IntakeHandler[R]:
    """Wrap ``handler``, which takes ``(body, intake=None)``, so :func:`deliver` hands it the
    context. Raises ``TypeError`` when ``handler`` takes no optional ``intake`` keyword."""
    return IntakeHandler(handler)


async def deliver[R](
    handler: Callable[[bytes], Awaitable[R]], raw: bytes, intake: IntakeContext | None
) -> R:
    """Call ``handler`` with ``raw``. An :class:`IntakeHandler`, which the runner starts a source
    with unless it declares ``wants_receipt``, is always given ``intake=`` too, ``None`` included.
    Any other handler, such as a test's one-argument fake, is called with the body alone."""
    if isinstance(handler, IntakeHandler):
        result: R = await handler(raw, intake=intake)
        return result
    return await handler(raw)
