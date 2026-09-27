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
:func:`_narrow_https_pools` names the proxy hops it leaves alone. It also changes how the reply BODY
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
"""

from __future__ import annotations

import http.client
import ssl
from collections.abc import Callable
from typing import Any

import requests
import requests.adapters
from urllib3.util.ssl_ import resolve_cert_reqs

from messagefoundry.transports.bounded_read import (
    DEFAULT_MAX_RESPONSE_BYTES,
    EgressReplyError,
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


#: Marks an https pool class :func:`_narrow_https_pools` already made, so a cached proxy manager
#: handed back again is not wrapped a second time.
_NARROWED_POOL_MARK = "_mefor_narrowed_tls"


def _narrow_https_pools(manager: Any, factory: Callable[[], ssl.SSLContext]) -> None:
    """Make ``manager``'s verifying https connections handshake on a fresh ``factory()`` context.

    BACKLOG #300. The context is set per CONNECTION, in ``connect``, not per pool, for the reasons
    ``tls_policy.assert_hvac_tls_suites`` gives. It subclasses the https pool class the manager
    already uses, not a fixed one, so a SOCKS proxy manager keeps its SOCKS connections. The dict is
    replaced, never changed in place, because a ``PoolManager`` shares urllib3's module-level dict.

    **A connection that will not verify is left alone.** requests sets ``CERT_NONE`` on one case
    only here, since the Vault clients refuse ``verify=False``: an ``http://`` Vault reached through
    an ``https://`` proxy, where this connection's TLS is to the proxy. The factory's context
    checks host names, so urllib3's ``CERT_NONE`` would raise on it. That hop keeps urllib3's own
    context, as it did before, and it is not a hop to Vault.

    **Not narrowed, at least: the TLS hop to an ``https://`` proxy in front of an ``https://``
    Vault.** urllib3 builds that context itself, from the proxy settings. The hop to Vault inside
    the tunnel is narrowed."""
    classes = dict(manager.pool_classes_by_scheme)
    base_pool = classes["https"]
    if getattr(base_pool, _NARROWED_POOL_MARK, False):
        return
    base_conn = base_pool.ConnectionCls

    def connect(self: Any) -> None:
        if resolve_cert_reqs(self.cert_reqs) != ssl.CERT_NONE:
            self.ssl_context = factory()
        base_conn.connect(self)

    conn_cls = type("NarrowedHTTPSConnection", (base_conn,), {"connect": connect})
    classes["https"] = type(
        "NarrowedHTTPSConnectionPool",
        (base_pool,),
        {"ConnectionCls": conn_cls, _NARROWED_POOL_MARK: True},
    )
    manager.pool_classes_by_scheme = classes


class StrictReplyAdapter(requests.adapters.HTTPAdapter):
    """A ``requests`` adapter that reads every reply body through ``bounded_read``.

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
        _narrow_https_pools(self.poolmanager, self._ssl_context_factory)

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        # A hop reached through a proxy takes its pools from the proxy manager instead. Without
        # this, an HTTPS_PROXY in the environment would take the hop back to urllib3's own wider
        # suite list.
        manager = super().proxy_manager_for(proxy, **proxy_kwargs)
        _narrow_https_pools(manager, self._ssl_context_factory)
        return manager

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
