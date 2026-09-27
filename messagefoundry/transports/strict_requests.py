# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Read a ``requests`` reply through :mod:`~messagefoundry.transports.bounded_read` (BACKLOG #2053).

The engine's three Vault and OpenBao clients (``config/secretprovider_vault.py``,
``store/keyprovider_vault.py`` and ``store/crypto_transit.py``, which shares the second one's
client) talk HTTP through ``hvac``, which talks through ``requests`` and ``urllib3``. None of that
stack went through ``bounded_read``, so on a first deployment a Vault reply would be read with no
byte bound, with ``urllib3``'s own chunk decoder (``int(line, 16)``), and with whatever framing
``http.client`` settled on after a malformed header line (ASVS 4.2.1, 15.2.2).

:class:`StrictReplyAdapter` is a ``requests`` transport adapter. :func:`mount_strict_reply_adapter`
puts it on the session ``hvac`` built, AFTER ``hvac.Client`` is constructed, so the TLS arguments
the suite assertion checked (``tls_policy.assert_hvac_tls_suites``) are still the ones the hop
uses. The adapter subclasses ``HTTPAdapter``. Since BACKLOG #300 it also gives each new verifying
https connection a fresh context from the factory that assertion returned, so every TLS handshake
with Vault runs on a narrowed, asserted context; urllib3 still applies requests' ``verify`` to it.
:func:`_narrowed_pool_classes` names the proxy hops it leaves alone. It also changes how the reply BODY
is read:

* The body is read eagerly, in :meth:`StrictReplyAdapter.build_response`, from the
  ``http.client.HTTPResponse`` under ``urllib3``'s response, by
  :func:`~messagefoundry.transports.bounded_read.read_bounded`. So the framing checks, the strict
  chunk decoder and the byte bound all apply, and ``urllib3``'s own body reader never runs.
* Each request asks for ``Accept-Encoding: identity`` and a reply with any other content coding is
  refused. ``requests`` would otherwise decompress ``gzip`` or ``deflate`` after the bound, so the
  bound would limit the wire bytes and not what the engine buffers.

**Connection reuse stays, and only a strictly complete read earns it** (the row's third limb).
The Transit cipher makes one Vault call per at-rest cell it encrypts or decrypts, so dropping reuse
would add a TLS handshake to every cell. After a clean read the body has ended exactly where its own
framing said, so the stream sits at the next reply's first byte and the connection goes back to the
pool. After ANY refusal, a body past the bound, a truncation or a framing fault, the connection is
closed rather than pooled, because its stream position is then unknown. What reuse still concedes:
a peer that sends MORE bytes than it framed. Extra bytes that arrive with the reply land in that
reply's own buffered reader and are dropped when it closes. Extra bytes already waiting on the
socket when the connection is next taken make ``urllib3`` discard it. Extra bytes that arrive later
than that would be read as the next reply. Only the peer itself, or an on-path writer on a hop with
no TLS, can send them, and either can already forge any reply outright. So reuse adds no capability
that the hop does not already concede.

**A socket failure during the eager read is raised as the** ``requests`` **exception it would have
been.** ``requests`` calls ``build_response`` outside the ``try`` that translates socket errors, so
a stall or reset mid-body would otherwise escape as a bare :class:`TimeoutError` or
:class:`OSError`.

**The reply HEAD is read strictly too (BACKLOG #2123).** By the time ``build_response`` runs,
``http.client`` has already parsed the status line and headers, so the body read above cannot see a
bare CR there. ``urllib3``'s connection builds its ``http.client`` response from the connection's
``response_class``, so the adapter's pools open connections whose ``response_class`` is #2052's
:class:`~messagefoundry.transports.bounded_read.StrictHTTPResponse`. That class refuses a bare CR as
the head is read. ``urllib3`` reports the refusal as a lost connection and closes that connection
rather than pooling it. :meth:`StrictReplyAdapter.send` finds the refusal inside the ``requests``
error and raises it as a
:class:`~messagefoundry.transports.bounded_read.MalformedReplyHeadError` naming the hop, so the
providers name the refusal and not a generic connection error. The connection classes subclass
``urllib3``'s own, so the constructor is unchanged. The https connection's TLS context is the
BACKLOG #300 one above: :func:`_narrowed_pool_classes` subclasses the strict-head class, so a
narrowed connection still reads its head strictly.

A pool whose connections would read the head with the stock class is refused before anything is
sent. The one such pool ``requests`` can build is a SOCKS proxy's, and that needs the PySocks
package, which the engine does not install. Without it ``requests`` refuses a SOCKS proxy itself.

**Not covered: an HTTP proxy's own CONNECT reply.** For an ``https`` target through an HTTP proxy,
``http.client`` reads the proxy's reply to ``CONNECT`` with ``_read_status`` and ``_read_headers``
and never calls ``begin``, so a bare CR there is not refused. That head frames no body the engine
reads, and the Vault reply that follows inside the tunnel is read strictly. #2052's urllib openers
have the same gap.
"""

from __future__ import annotations

import http.client
import ssl
from collections.abc import Callable
from typing import Any

import requests
import requests.adapters
import urllib3.connection
import urllib3.connectionpool
import urllib3.poolmanager
from urllib3.util.ssl_ import resolve_cert_reqs

from messagefoundry.transports.bounded_read import (
    DEFAULT_MAX_RESPONSE_BYTES,
    EgressReplyError,
    MalformedReplyHeadError,
    StrictHTTPResponse,
    read_bounded,
)

__all__ = [
    "MAX_VAULT_REPLY_BYTES",
    "StrictReplyAdapter",
    "mount_strict_reply_adapter",
]

#: Ceiling on one reply body on the Vault or OpenBao Transit client.
#:
#: **Deliberately larger than** ``bounded_read.DEFAULT_MAX_RESPONSE_BYTES`` **(16 MiB).** A Transit
#: ``encrypt`` or ``decrypt`` reply carries one stored cell as base64, which is 4/3 of the cell, and
#: a cell can be a whole message up to that same 16 MiB. So the shared ceiling would refuse an honest
#: reply for any message past about 12 MiB. 64 MiB is twice the 32 MiB that Vault and OpenBao accept
#: as a request body by default (the listener's ``max_request_size``). A Transit reply is about the
#: size of the request it answers, so every reply to a request those servers accept at their
#: defaults fits, with room for the JSON around it. A site that raises both the engine's message cap
#: and Vault's request cap past that would see the largest cells refused, which fails closed.
MAX_VAULT_REPLY_BYTES = 64 * 1024 * 1024


class _StrictHeadHTTPConnection(urllib3.connection.HTTPConnection):
    response_class = StrictHTTPResponse


class _StrictHeadHTTPSConnection(urllib3.connection.HTTPSConnection):
    response_class = StrictHTTPResponse


class _StrictHeadHTTPConnectionPool(urllib3.connectionpool.HTTPConnectionPool):
    ConnectionCls = _StrictHeadHTTPConnection


class _StrictHeadHTTPSConnectionPool(urllib3.connectionpool.HTTPSConnectionPool):
    ConnectionCls = _StrictHeadHTTPSConnection


_STRICT_CONNECTIONS = (_StrictHeadHTTPConnection, _StrictHeadHTTPSConnection)

#: Set on the https pool class :func:`_narrowed_pool_classes` makes. The pre-send check in
#: :meth:`StrictReplyAdapter.get_connection_with_tls_context` refuses an https pool without it.
_NARROWED_POOL_MARK = "_mefor_narrowed_tls"


def _narrowed_pool_classes(
    factory: Callable[[], ssl.SSLContext],
) -> dict[str, type[urllib3.connectionpool.HTTPConnectionPool]]:
    """The pool classes one adapter's managers use, replacing ``urllib3``'s module-level map.

    Strict heads on both schemes (#2123), and a narrowed context on https.

    BACKLOG #300 on top of #2123. The https connection subclasses the strict-head one, so it keeps
    :class:`StrictHTTPResponse`, and sets a fresh ``factory()`` context in ``connect``. It is per
    CONNECTION, not per pool, for the reasons ``tls_policy.assert_hvac_tls_suites`` gives. Built
    ONCE per adapter and assigned whole, so a manager's classes are never briefly un-narrowed while
    another thread builds a pool from them.

    **A connection that will not verify is left alone.** requests sets ``CERT_NONE`` on one case
    only here, since the Vault clients refuse ``verify=False``: an ``http://`` Vault reached through
    an ``https://`` proxy, where this connection's TLS is to the proxy. The factory's context
    checks host names, so urllib3's ``CERT_NONE`` would raise on it. That hop keeps urllib3's own
    context, as it did before, and it is not a hop to Vault.

    **Not narrowed, at least: the TLS hop to an ``https://`` proxy in front of an ``https://``
    Vault.** urllib3 builds that context itself, from the proxy settings. The hop to Vault inside
    the tunnel is narrowed."""

    class NarrowedHTTPSConnection(_StrictHeadHTTPSConnection):
        def connect(self) -> None:
            if resolve_cert_reqs(self.cert_reqs) != ssl.CERT_NONE:
                self.ssl_context = factory()
            super().connect()

    class NarrowedHTTPSConnectionPool(_StrictHeadHTTPSConnectionPool):
        ConnectionCls = NarrowedHTTPSConnection

    setattr(NarrowedHTTPSConnectionPool, _NARROWED_POOL_MARK, True)
    return {"http": _StrictHeadHTTPConnectionPool, "https": NarrowedHTTPSConnectionPool}


def _head_refusal_in(exc: BaseException) -> MalformedReplyHeadError | None:
    """The head refusal ``urllib3`` and ``requests`` wrapped, if ``exc`` carries one.

    ``urllib3`` wraps it in a ``ProtocolError``'s arguments, and ``requests`` wraps that in a
    ``ConnectionError``'s. ``__cause__`` is walked as well, so a later release that moves it from
    the arguments to an explicit cause is still found. ``__context__`` is NOT walked: a request sent
    while the caller handles an earlier refusal carries that refusal as its context, and an
    unrelated failure would then be relabelled as a head refusal.
    """
    seen: set[int] = set()
    pending: list[object] = [exc]
    while pending:
        item = pending.pop()
        if not isinstance(item, BaseException) or id(item) in seen:
            continue
        if isinstance(item, MalformedReplyHeadError):
            return item
        seen.add(id(item))
        pending.extend(item.args)
        pending.append(item.__cause__)
    return None


class StrictReplyAdapter(requests.adapters.HTTPAdapter):
    """A ``requests`` adapter that reads every reply head and body strictly.

    The head is read by ``StrictHTTPResponse`` on every connection the adapter's pools open, and a
    pool that would read it any other way is refused before sending. A bare CR in the head raises
    ``MalformedReplyHeadError`` from :meth:`send`, not the ``requests.ConnectionError`` that
    ``requests`` wraps it in. The body is read through ``bounded_read``.

    ``connector`` names the hop in every refusal. It must be a fixed, operator-facing label, never a
    URL, a token or a body, because it is carried into exception text.

    ``ssl_context_factory`` builds the TLS context for each new verifying https connection (BACKLOG
    #300). It is REQUIRED, so no caller can build this adapter and silently get urllib3's own wider
    suite list.
    The Vault clients pass the factory ``tls_policy.assert_hvac_tls_suites`` returned, which narrows
    and asserts every context it builds.
    """

    #: requests copies an adapter's state through these names, then rebuilds its pool manager, so
    #: the factory must travel with them or a deep copy would not narrow. Pickling is refused, not
    #: supported: the shipped factory is a closure, and pickle raises on it.
    __attrs__ = [
        *requests.adapters.HTTPAdapter.__attrs__,
        "_ssl_context_factory",
        "_pool_classes",
        "_connector",
        "_limit",
    ]

    def __init__(
        self,
        *,
        connector: str,
        ssl_context_factory: Callable[[], ssl.SSLContext],
        limit: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        # Set BEFORE super().__init__(), which builds the pool manager through init_poolmanager.
        self._ssl_context_factory = ssl_context_factory
        self._pool_classes = _narrowed_pool_classes(ssl_context_factory)
        super().__init__()
        self._connector = connector
        self._limit = limit

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = requests.adapters.DEFAULT_POOLBLOCK,
        **pool_kwargs: Any,
    ) -> None:
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)
        # The strict-head classes (#2123), with the https one narrowed on top (#300).
        self.poolmanager.pool_classes_by_scheme = self._pool_classes

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        manager = super().proxy_manager_for(proxy, **proxy_kwargs)
        # Only a plain proxy manager's pools are the stock ones. A SOCKS manager's pools open SOCKS
        # connections, and swapping them would send around the proxy, so those are left alone and
        # refused below.
        # The same dict every call, so a cached manager is never re-wrapped (BACKLOG #300).
        if type(manager) is urllib3.poolmanager.ProxyManager:
            manager.pool_classes_by_scheme = self._pool_classes
        return manager

    def get_connection_with_tls_context(
        self,
        request: requests.PreparedRequest,
        verify: Any,
        proxies: dict[str, str] | None = None,
        cert: Any = None,
    ) -> urllib3.connectionpool.HTTPConnectionPool:
        pool = super().get_connection_with_tls_context(request, verify, proxies=proxies, cert=cert)
        # Both halves: the class is one of ours, and nothing below it put the stock reader back.
        if not (
            issubclass(pool.ConnectionCls, _STRICT_CONNECTIONS)
            and issubclass(pool.ConnectionCls.response_class, StrictHTTPResponse)
        ):
            raise EgressReplyError(
                f"{self._connector} would read its reply head with a connection the engine cannot "
                "make strict; refusing to send"
            )
        # BACKLOG #300, the same fail-closed shape: an https pool must be the narrowed one.
        if pool.scheme == "https" and not getattr(type(pool), _NARROWED_POOL_MARK, False):
            raise EgressReplyError(
                f"{self._connector} would handshake on a TLS context the engine did not narrow; "
                "refusing to send"
            )
        return pool

    def send(
        self, request: requests.PreparedRequest, *args: Any, **kwargs: Any
    ) -> requests.Response:
        try:
            return super().send(request, *args, **kwargs)
        except requests.exceptions.ConnectionError as exc:
            refusal = _head_refusal_in(exc)
            if refusal is None:
                raise
            raise MalformedReplyHeadError(
                f"{self._connector} framed its reply head ambiguously ({refusal.reason}); "
                "refusing to read it",
                reason=refusal.reason,
            ) from exc

    def add_headers(self, request: requests.PreparedRequest, **kwargs: Any) -> None:
        # The hook requests documents for exactly this, called on every send before the request is
        # written. Replaces the session's default, which offers gzip and deflate.
        request.headers["Accept-Encoding"] = "identity"

    def build_response(self, req: requests.PreparedRequest, resp: Any) -> requests.Response:
        response = super().build_response(req, resp)
        # On every failure below the stream position is unknown, so the connection must not go
        # back to the pool. Response.close() closes it, because no content was consumed.
        try:
            body = self._read_body(resp)
        except TimeoutError as exc:
            response.close()
            raise requests.exceptions.ReadTimeout(exc, request=req) from exc
        except (OSError, http.client.HTTPException) as exc:
            response.close()
            raise requests.exceptions.ConnectionError(exc, request=req) from exc
        except BaseException:
            response.close()
            raise
        # The two attributes requests.Response.content reads. With them set, the body is never read
        # again, and urllib3's own reader never runs.
        response._content = body
        response._content_consumed = True
        # The body ended where its framing said, so the stream is at the next reply's first byte.
        resp.release_conn()
        return response

    def _read_body(self, resp: Any) -> bytes:
        # `_original_response` is urllib3's name for the http.client.HTTPResponse it wraps.
        # requests reads the same attribute to extract cookies, so it is not a name only this
        # module depends on. Anything else is refused rather than read some other way.
        reply = getattr(resp, "_original_response", None)
        if not isinstance(reply, http.client.HTTPResponse):
            raise EgressReplyError(
                f"{self._connector} returned a reply the engine cannot read strictly; refusing it"
            )
        codings = {
            c.strip(" \t").lower()
            for field in reply.headers.get_all("Content-Encoding") or []
            for c in str(field).split(",")
        }
        if codings - {"", "identity"}:
            raise EgressReplyError(
                f"{self._connector} sent a content coding the engine did not ask for; "
                "refusing to read it"
            )
        body = read_bounded(reply, limit=self._limit, connector=self._connector)
        # A body framed by connection close is still open here; the other framings closed it at
        # their end. Closing the reply closes its buffered reader, not urllib3's socket.
        reply.close()
        return body


def mount_strict_reply_adapter(
    client: Any,
    *,
    connector: str,
    ssl_context_factory: Callable[[], ssl.SSLContext],
    limit: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> None:
    """Mount :class:`StrictReplyAdapter` for both schemes on ``client``'s ``requests`` session.

    ``client`` is an ``hvac.Client``. Its session is ``client.adapter.session``, which ``hvac``
    built from the TLS arguments the caller has already asserted. Raises :class:`ValueError` when
    that session cannot be found, so a client the strict reader cannot reach fails closed at
    construction instead of reading leniently.

    ``ssl_context_factory`` is the factory ``tls_policy.assert_hvac_tls_suites`` returned (BACKLOG
    #300). It is REQUIRED, so a caller cannot mount the reader and forget the narrowing. The adapter
    calls it for each new verifying https connection.

    ``limit`` is the reply ceiling. The Transit client passes :data:`MAX_VAULT_REPLY_BYTES`; the KV
    client reads small secrets and keeps the shared egress ceiling.
    """
    session = getattr(getattr(client, "adapter", None), "session", None)
    if not isinstance(session, requests.Session):
        raise ValueError(
            f"{connector}: cannot mount the strict reply reader, because the Vault client exposes "
            f"no requests session at client.adapter.session"
        )
    adapter = StrictReplyAdapter(
        connector=connector, limit=limit, ssl_context_factory=ssl_context_factory
    )
    for prefix in ("https://", "http://"):
        session.mount(prefix, adapter)
