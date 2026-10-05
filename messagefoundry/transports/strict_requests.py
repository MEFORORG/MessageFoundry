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
with Vault runs on a narrowed, asserted context holding requests' CA. That includes the TLS leg to
an ``https://`` proxy; :func:`_narrowed_pool_classes` says how the CA gets there, and which proxy
shape is refused. It also changes how the reply BODY is read:

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

**A bare CR in an HTTP proxy's own CONNECT reply is refused too (vault BACKLOG #2170).**
``StrictHTTPResponse`` says how, and what else on that head is not checked. It is refused before
anything enters the tunnel, and
:meth:`StrictReplyAdapter.send` names it like any other head refusal. On this hop that rests on
``urllib3`` calling ``http.client``'s own ``_tunnel``, as it does on the Python this engine requires.
``tests/test_proxy_connect_reply_head.py`` measures it on the wire, so a ``urllib3`` that brought its
own would turn that test red.
"""

from __future__ import annotations

import http.client
import re
import socket
import ssl
import urllib.parse
from collections.abc import Callable
from typing import Any

import requests
import requests.adapters
import requests.utils
import urllib3.connection
import urllib3.connectionpool
import urllib3.exceptions
import urllib3.poolmanager
import urllib3.util
from urllib3.util.ssl_ import resolve_cert_reqs

from messagefoundry.config.tls_policy import (
    InsecureHopRefused,
    enforce_insecure_hop,
    insecure_hop_disposition,
    is_loopback_hop_host,
)
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
    factory: Callable[[], ssl.SSLContext], *, connector: str
) -> dict[str, type[urllib3.connectionpool.HTTPConnectionPool]]:
    """The pool classes one adapter's managers use, replacing ``urllib3``'s module-level map.

    Strict heads on both schemes (#2123), and a narrowed context on https.

    BACKLOG #300 on top of #2123. The https connection subclasses the strict-head one, so it keeps
    :class:`StrictHTTPResponse`, and sets a fresh ``factory()`` context in ``connect``. It is per
    CONNECTION, not per pool, for the reasons ``tls_policy.assert_hvac_tls_suites`` gives. Built
    ONCE per adapter and assigned whole, so a manager's classes are never briefly un-narrowed while
    another thread builds a pool from them.

    **The TLS hop to an** ``https://`` **proxy gets its own fresh context from the same factory**
    (BACKLOG #300, the proxy limb). requests honours ``HTTPS_PROXY``, ``ALL_PROXY`` and, on
    Windows, the Internet Settings proxy by default, so an operator's proxy reaches this client with
    no engine setting. An ``https://`` Vault through an ``https://`` proxy then has two TLS legs:
    one to the proxy, and one to Vault inside the ``CONNECT`` tunnel. urllib3 builds the first from
    the pool's ``ProxyConfig.ssl_context``, which requests leaves ``None``, and ``None`` means
    urllib3's own unnarrowed context. So each connection replaces that field on its OWN copy of the
    config with ``factory()``. ``server_hostname`` on that leg is the proxy's host.

    **The connection loads requests' CA onto the proxy leg's context itself**, so that leg verifies
    against the Vault hop's anchor. Up to urllib3 2.7.0, urllib3 loaded the connection's CA onto a
    supplied context on both legs. urllib3 2.8.0 loads no CA onto a supplied PROXY context, so
    without this load the proxy handshake fails verification. It still loads the CA on the Vault
    leg, so the engine does not load it there too: one read of the CA file per leg, at handshake
    time. A later urllib3 that stopped loading it on the Vault leg as well would fail closed, since
    the factory's contexts require a verified peer, and the on-wire tests would go red.

    requests forwards through an ``https://`` proxy only for an ``http://`` Vault, and that shape is
    refused below, before any socket opens.

    **It is then CHECKED, not assumed.** The proxy leg's ``SSLSocket`` must hold exactly that
    context, and urllib3 must report the proxy verified. The ``ProxyConfig`` field is urllib3's
    documented one, but which object the proxy handshake reads is not, so a urllib3 that stopped
    reading it would otherwise fall back to its own context with nothing reporting it. The check runs
    in urllib3's ``_connect_tls_proxy`` hook, before ``CONNECT`` and any proxy credentials cross the
    leg. That hook is private, so it runs again after ``connect``, which still refuses if a later
    urllib3 renames the hook, though only after ``CONNECT``. That second check reads the proxy leg
    through ``SSLTransport.socket``, also urllib3's own name. If that changes, every tunnelled
    connection is refused: it fails closed, never open.

    **A connection that will not verify is refused before its socket opens.** The Vault clients
    refuse ``verify=False``, so requests sets ``CERT_NONE`` on one case only: an ``http://`` Vault
    reached through an ``https://`` proxy, where requests clears the CA for the ``http://`` URL. That
    connection's only TLS leg is to the proxy, and it carries the token. It used to keep urllib3's own
    unverified context. The adapter refuses that case first, by name (:func:`_unverifiable_proxy_leg`);
    this is the backstop."""

    class NarrowedHTTPSConnection(_StrictHeadHTTPSConnection):
        #: The context this connection supplied for its proxy leg; ``None`` when it has none.
        _mefor_proxy_context: ssl.SSLContext | None = None

        def connect(self) -> None:
            if resolve_cert_reqs(self.cert_reqs) == ssl.CERT_NONE:
                raise EgressReplyError(
                    f"{connector} would open a TLS session that verifies no peer; "
                    "refusing to connect"
                )
            self._mefor_proxy_context = self._narrow_the_proxy_leg()
            self.ssl_context = factory()
            super().connect()
            if self._mefor_proxy_context is not None:
                # Through a tunnel, urllib3 wraps the Vault leg in an SSLTransport over the proxy
                # leg's SSLSocket, which it names `socket`.
                self._check_the_proxy_leg(getattr(self.sock, "socket", None))

        def _narrow_the_proxy_leg(self) -> ssl.SSLContext | None:
            """Give the TLS leg to an https proxy its own context, or ``None`` if it has none."""
            if (
                self.proxy is None
                or self.proxy.scheme != "https"
                or not self.proxy_is_tunneling
                or self.proxy_config is None
            ):
                return None
            context = factory()
            # The Vault anchor; the docstring above says why the connection loads it here.
            if self.ca_certs or self.ca_cert_dir or self.ca_cert_data:
                try:
                    context.load_verify_locations(
                        self.ca_certs, self.ca_cert_dir, self.ca_cert_data
                    )
                except OSError as exc:
                    # urllib3 wraps this the same way when it loads the CA, so an unreadable CA
                    # file still reaches requests as an SSLError, not a connection error.
                    raise urllib3.exceptions.SSLError(exc) from exc
            # _replace builds a new tuple, so the pool's shared config is never changed.
            self.proxy_config = self.proxy_config._replace(ssl_context=context)
            return context

        def _connect_tls_proxy(self, hostname: str, sock: socket.socket) -> ssl.SSLSocket:
            leg = super()._connect_tls_proxy(hostname, sock)
            self._check_the_proxy_leg(leg)
            return leg

        def _check_the_proxy_leg(self, leg: object) -> None:
            expected = self._mefor_proxy_context
            if (
                expected is not None
                and isinstance(leg, ssl.SSLSocket)
                and leg.context is expected
                and self.proxy_is_verified is True
            ):
                return
            if isinstance(leg, ssl.SSLSocket):
                leg.close()
            self.close()
            raise EgressReplyError(
                f"{connector}: the TLS leg to its https:// proxy did not run on the engine's "
                "narrowed, verifying context; refusing to send"
            )

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
        self._pool_classes = _narrowed_pool_classes(ssl_context_factory, connector=connector)
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
        # BACKLOG #2547, before each send: checked at construction too; this catches a proxy that
        # appeared since. get_connection_with_tls_context checks first, before requests parses the
        # URL. This second check is where requests reads credentials out of the proxy URL (the
        # Proxy-Authorization header, or the SOCKS user and password), on every proxied request on
        # any requests version, before any connection opens and before a manager is cached.
        _refuse_cleartext_proxy_credentials(proxy, connector=self._connector)
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
        # BACKLOG #2547, before requests parses the proxy URL: a credentialed URL that will not
        # parse would otherwise fail in requests' own parser, whose error can quote the password.
        # proxy_manager_for checks again, on a requests too old to call this hook.
        _refuse_cleartext_proxy_credentials(
            requests.utils.select_proxy(request.url or "", proxies), connector=self._connector
        )
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
        # BACKLOG #300: an https pool for an http:// request can only be an https proxy's, and
        # requests will not verify it. Checked at construction too; this also catches a proxy
        # setting that changed after the client was built.
        url = request.url or ""
        if _scheme_of(url) != "https":
            if pool.scheme == "https":
                raise EgressReplyError(_unverifiable_proxy_leg(self._connector))
            # BACKLOG #2317: a non-https request carries the token in cleartext unless it stays
            # on the box. Checked at construction too; this catches a proxy that appeared since.
            _refuse_a_cleartext_vault_hop(
                url, requests.utils.select_proxy(url, proxies), connector=self._connector
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


def _scheme_of(url: str | None) -> str:
    return urllib.parse.urlsplit(url or "").scheme.lower()


def _unverifiable_proxy_leg(connector: str) -> str:
    return (
        f"{connector}: an http:// Vault address would be reached through an https:// proxy "
        "(from HTTP_PROXY, ALL_PROXY or the system proxy settings). requests does not verify that "
        "proxy's certificate for an http:// address, so the TLS leg carrying the Vault token "
        "would authenticate nobody. Use an https:// Vault address, which tunnels through the "
        "proxy with both TLS legs verified and narrowed; refusing (BACKLOG #300)"
    )


#: The fixed text of the cleartext refusal. It names no part of the address, so a refusal that
#: reaches a log or a CLI never echoes a host, a port or credentials an operator put in the URL.
_CLEARTEXT_VAULT_HOP = (
    "the Vault address is not a well-formed https:// URL. Over http:// the Vault token would "
    "cross the network in cleartext, and only a loopback Vault reached with no proxy may use it. "
    "Use an https:// Vault address; refusing (BACKLOG #2317)"
)


def _vault_scheme_and_host(url: str) -> tuple[str, str]:
    """The scheme and host urllib3 would dial for ``url``, lower-cased, or two blanks.

    Parsed with ``urllib3.util.parse_url``, the parser requests' ``prepare_url`` uses, and NOT
    with ``urllib.parse``. The two disagree on at least a backslash before ``@``: ``urlsplit``
    reads ``http://a\\@127.0.0.1`` as host ``127.0.0.1``, while urllib3 dials ``a``. A check
    that parsed one way while the client dialled the other would pass a remote address as on-box.
    An address that will not parse gives two blanks rather than an error, because urllib3's error
    text quotes the address; blanks are refused like any other non-https address."""
    try:
        parts = urllib3.util.parse_url(url)
    except ValueError:  # LocationParseError
        return "", ""
    return (parts.scheme or "").lower(), (parts.host or "").strip("[]")


def _refuse_a_cleartext_vault_hop(url: str, proxy: str | None, *, connector: str) -> None:
    """Refuse a Vault hop whose token would cross the network in cleartext (BACKLOG #2317).

    ``url`` is the Vault address and ``proxy`` the proxy requests would send it through, or
    ``None``. An ``https://`` address returns at once: its token rides inside TLS to Vault, with or
    without a proxy in front, and :func:`_narrowed_pool_classes` covers both legs. Anything else
    goes to the shared cleartext-hop authority, ``tls_policy.insecure_hop_disposition``, which
    ALLOWs only an on-box hop. Here that means an ``http://`` address whose host passes
    ``tls_policy.is_loopback_hop_host``, which never resolves DNS, AND that requests would reach
    with no proxy. A loopback address sent through a proxy is not on
    the box: the proxy reads the request, token and all. A host-less address is not counted as
    loopback, because it names no hop at all.

    **So the authority reduces to "on the box, or refused".** This hop has no posture in scope:
    the providers are built from the environment and hold no ``[security]`` section (see
    ``tls_policy.vault_client_verify_kwargs``), and it has no attestation or acceptance field. So
    a non-loopback ``http://`` Vault is refused under every ``[security].enforcement`` setting,
    like this hop's two older refusals (an ``https://`` proxy in front of an ``http://`` Vault, and
    ``verify=False``), neither of which has an escape. The HTTP-family sibling is
    ``transports.rest``'s ``_hop_guard_host``; it echoes the host and has no proxy arm, so it is
    not reused here. That family needs no proxy arm in its guard: its openers dial a loopback
    host direct (``bounded_read.LoopbackDirectProxyHandler``, vault BACKLOG #2579). requests
    has no such handler, which is why this hop refuses instead.

    Raises :class:`~messagefoundry.config.tls_policy.InsecureHopRefused`, a ``ValueError``, with
    fixed text."""
    scheme, host = _vault_scheme_and_host(url)
    if scheme == "https":
        return
    on_box = scheme == "http" and not proxy and bool(host) and is_loopback_hop_host(host)
    enforce_insecure_hop(
        insecure_hop_disposition(
            enforcing=True,  # no posture in scope (docstring); fail closed
            is_loopback_hop=on_box,
            hop_attested=False,
            cleartext_accepted=False,
        ),
        message=_CLEARTEXT_VAULT_HOP,
        cell=connector,
    )


#: The fixed text of the proxy-credential refusal. Like the cleartext one, it names no part of the
#: proxy URL, because the part it is about is a password.
_CLEARTEXT_PROXY_CREDENTIALS = (
    "the proxy in front of the Vault address carries credentials in its URL and is not an "
    "https:// proxy, or its URL cannot be read. requests would send those credentials to the "
    "proxy in cleartext. Use an https:// proxy, or a proxy that takes no credentials in its URL; "
    "refusing (BACKLOG #2547)"
)


def _proxy_carries_cleartext_credentials(proxy: str) -> bool:
    """Whether requests would send credentials from ``proxy``'s URL over a hop with no TLS.

    **Any** ``@`` **in the URL counts as credentials.** User information needs a literal ``@``, so
    this misses none. It also catches URLs the parsers read in ways that hide them. requests
    re-reads a scheme-less ``user:pw@host:3128`` as scheme ``user``, and a backslash before the
    ``@`` moves the user name into the host. Neither proxy works, and an operator who wrote either
    meant to send credentials, so it is refused here with fixed text rather than failing later on a
    parser error that quotes the URL.

    The scheme is read the way requests reads it before building the proxy's pool: a missing one
    becomes ``http`` (``prepend_scheme_if_needed``), parsed by ``urllib3.util.parse_url``. Only an
    ``https://`` proxy carries credentials inside TLS. Every other scheme sends them in the clear,
    ``http`` in a ``Proxy-Authorization`` header and ``socks`` in the SOCKS greeting. A URL that will
    not parse counts as not ``https://``.

    ``transports.rest.proxy_url_sends_userinfo`` (BACKLOG #1182) asks a similar question for the
    urllib egress and is not reused. It reads the URL as urllib's ``ProxyHandler`` does, which is a
    different client library, and it answers what a user-declared ``proxy_url`` sends. This one
    fails closed on a URL from the environment that nobody declared."""
    if "@" not in proxy:
        return False
    try:
        scheme = urllib3.util.parse_url(
            requests.utils.prepend_scheme_if_needed(proxy, "http")
        ).scheme
    except ValueError:  # LocationParseError
        return True
    return (scheme or "").lower() != "https"


def _refuse_cleartext_proxy_credentials(proxy: str | None, *, connector: str) -> None:
    """Refuse a Vault hop whose proxy would receive its credentials in cleartext (BACKLOG #2547).

    ``proxy`` is the proxy requests would send the hop through, or ``None``. An ``https://``
    Vault behind an ``http://`` proxy keeps its token inside the TLS tunnel, which is why
    :func:`_refuse_a_cleartext_vault_hop` allows it. But a ``user:password@`` in that proxy's URL
    is sent to the proxy itself, in the clear, on the ``CONNECT`` that opens the tunnel. Behind a
    SOCKS proxy it goes in the SOCKS greeting instead, also in the clear.

    Refused under every ``[security].enforcement`` setting, for the reason the cleartext refusal
    gives: this hop has no posture in scope and no acceptance field. There is no loopback
    exception. Raises :class:`~messagefoundry.config.tls_policy.InsecureHopRefused` with fixed
    text."""
    if proxy and _proxy_carries_cleartext_credentials(proxy):
        raise InsecureHopRefused(f"{connector}: {_CLEARTEXT_PROXY_CREDENTIALS}")


def _prepared_vault_hop(
    session: requests.Session, url: object, request_proxies: object = None
) -> tuple[str, str | None] | None:
    """The URL requests would send for ``url`` and the proxy it would pick, or ``None``.

    ``None`` means the address cannot be read as one URL: it is not a string, requests will not
    prepare it, a parser rejects it, or the raw address and the prepared one name different hosts
    (a backslash before ``@`` does that, and the trust anchor is resolved from the raw one). The
    caller refuses ``None`` with fixed text, because the errors those parsers raise quote the
    address.

    The URL is prepared exactly as requests prepares one before sending (``prepare_url``), so the
    build-time decision is made on the same URL the send-time check sees. The proxy comes from the
    two calls ``Session.request`` makes, in its order: ``request_proxies`` (the proxies the client
    passes with every request; hvac passes its configured ones), then the environment and, on
    Windows, the Internet Settings proxy, minus ``NO_PROXY``, then the session's own proxies.

    It is looked up for an ``https://`` address too, because that proxy's URL can carry
    credentials (BACKLOG #2547). If the lookup itself fails, an ``https://`` address goes on with no
    proxy, because the adapter's send-time check still sees whatever proxy the send picks. Any
    other address behaves as before: refused on a ``ValueError`` or a requests error, and the error
    raised as it is otherwise, since its own text points at the proxy settings."""
    if not isinstance(url, str):
        return None
    try:
        prepared = requests.PreparedRequest()
        prepared.prepare_url(url, None)
        sent = prepared.url or ""
        if urllib.parse.urlsplit(url.strip()).hostname != urllib.parse.urlsplit(sent).hostname:
            return None
    except (ValueError, requests.exceptions.RequestException):
        return None
    # A copy: merge_environment_settings writes the environment's proxies into the dict it gets.
    proxies = dict(request_proxies) if isinstance(request_proxies, dict) else {}
    try:
        settings = session.merge_environment_settings(sent, proxies, None, None, None)
        return sent, requests.utils.select_proxy(sent, settings["proxies"])
    except (ValueError, requests.exceptions.RequestException):
        return (sent, None) if _scheme_of(sent) == "https" else None
    # re.error: proxy_bypass_registry compiles each Windows ProxyOverride entry as a pattern.
    except (OSError, re.error):
        if _scheme_of(sent) == "https":
            return sent, None
        raise


def _refuse_an_insecure_vault_hop(
    session: requests.Session,
    url: object,
    *,
    connector: str,
    request_proxies: object = None,
) -> None:
    """Refuse at construction a Vault hop that would send its token or proxy credentials unprotected.

    Three refusals, in this order, on the URL and proxy :func:`_prepared_vault_hop` returns. It is
    the order the send-time checks run in, so a hop gets the same refusal at both points:

    * A proxy whose URL carries credentials and is not ``https://``, whatever the Vault address
      (:func:`_refuse_cleartext_proxy_credentials`, BACKLOG #2547).
    * An ``https://`` proxy in front of an ``http://`` Vault, for the reason
      :func:`_unverifiable_proxy_leg` gives (BACKLOG #300).
    * Anything :func:`_refuse_a_cleartext_vault_hop` refuses (BACKLOG #2317): a direct ``http://``
      address that is not loopback, any ``http://`` address behind a proxy, and an address that
      cannot be read as one URL.

    An ``https://`` Vault needs no more; :func:`_narrowed_pool_classes` covers its proxy leg. All
    three raise :class:`~messagefoundry.config.tls_policy.InsecureHopRefused`, outside any
    ``except``, so none carries a parser error that quotes the address. The proxy settings can
    change after this runs, so the adapter checks again before each send."""
    hop = _prepared_vault_hop(session, url, request_proxies)
    sent, proxy = hop if hop is not None else ("", None)
    _refuse_cleartext_proxy_credentials(proxy, connector=connector)
    if _scheme_of(sent) == "http" and proxy and _scheme_of(proxy) == "https":
        raise InsecureHopRefused(_unverifiable_proxy_leg(connector))
    _refuse_a_cleartext_vault_hop(sent, proxy, connector=connector)


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

    Also raises :class:`~messagefoundry.config.tls_policy.InsecureHopRefused`, a
    :class:`ValueError`, when the Vault address is not ``https://``, unless it is loopback and
    reached with no proxy (BACKLOG #2317), and when requests would send an ``http://`` Vault
    address through an ``https://`` proxy, whose TLS leg requests would not verify (BACKLOG #300),
    and when requests would send the Vault hop, of any scheme, through a proxy whose URL carries
    credentials and is not ``https://``, which would send those credentials in cleartext (BACKLOG
    #2547). At least the three Vault clients the engine builds today call this; a new one must too.
    """
    session = getattr(getattr(client, "adapter", None), "session", None)
    if not isinstance(session, requests.Session):
        raise ValueError(
            f"{connector}: cannot mount the strict reply reader, because the Vault client exposes "
            f"no requests session at client.adapter.session"
        )
    # hvac keeps the proxies it passes with every request in `_kwargs`, private but the only place
    # they live. Read here so the build-time proxy is the one the send picks; when the attribute
    # is missing, the adapter's send-time checks still cover them. A test pins the name.
    request_kwargs = getattr(client.adapter, "_kwargs", None)
    _refuse_an_insecure_vault_hop(
        session,
        getattr(client.adapter, "base_uri", None),
        connector=connector,
        request_proxies=(
            request_kwargs.get("proxies") if isinstance(request_kwargs, dict) else None
        ),
    )
    adapter = StrictReplyAdapter(
        connector=connector, limit=limit, ssl_context_factory=ssl_context_factory
    )
    for prefix in ("https://", "http://"):
        session.mount(prefix, adapter)
