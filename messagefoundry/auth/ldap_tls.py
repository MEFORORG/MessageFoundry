# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine's ``ldap3.Tls``: LDAPS wraps its socket with a context the engine built (BACKLOG #2494).

ldap3 2.9.1 builds its TLS context inside ``Tls.wrap_socket`` and offers no parameter to supply one.
Its only suite lever, ``ciphers=``, reaches TLS 1.2 and not TLS 1.3, so on Python 3.15 the LDAPS hop
could not drop ``TLS_AES_128_GCM_SHA256`` and the engine refused to bind. :class:`NarrowedTls`
replaces the one method that builds the context. The context comes from
:func:`messagefoundry.config.tls_policy.assert_ldap3_tls_suites`, whose docstring says what it holds.

**What is copied from ldap3, and why.** The wrap step below is ldap3's own, for the arguments the
engine passes: wrap the socket client-side, then, on a handshake with verification on, run ldap3's
host name check. That check is ldap3's function, called, not copied. **Deliberate differences, at
least these; keep each when re-deriving.** When that check refuses, this copy closes the TLS socket
before it re-raises, where ldap3 leaves it open while the error's traceback is held. ldap3's
``Connection.open`` re-raises a copy without the traceback, so on that path it was freed promptly
anyway (BACKLOG #3017). The ClientHello names the host the connection dials, in the form
:func:`_sni_name` gives, where ldap3 sends its ``sni`` attribute, normally none; this copy never
reads ``sni``, and nothing in the engine sets it. The host name check runs against the host less
its trailing dot, where ldap3 checks it as written (BACKLOG #6879).
The alternative was to patch ``ldap3.core.tls.create_default_context`` for the length of one call.
That is a module global, and ``AuthService`` runs binds on worker threads, so two concurrent binds
could each see the other's patch. ``tests/test_ldap_tls.py`` pins the source of ldap3's
``wrap_socket``, so an ldap3 that changes it goes red rather than drifting from this copy.

Imported lazily by :mod:`messagefoundry.auth.ldap`, like ldap3 itself, so a local-only deployment
never loads it.
"""

from __future__ import annotations

import logging
import socket
import ssl
import threading
from typing import Any

import ldap3
from ldap3.core.tls import check_hostname

from messagefoundry.config.tls_policy import assert_ldap3_tls_suites
from messagefoundry.netaddr import host_address

__all__ = ["NarrowedTls"]

logger = logging.getLogger(__name__)

#: The context refusals logged since a context last built, so a bind that fails the same way on
#: every connection logs once, and the same fault coming back after a recovery logs again. Binds
#: run on worker threads, hence the lock.
_REFUSALS_LOGGED: set[str] = set()
_REFUSALS_LOCK = threading.Lock()


def _warn_context_refusal(text: str) -> None:
    """Log a bind's context refusal at WARNING, once per text until a context builds again."""
    with _REFUSALS_LOCK:
        if text in _REFUSALS_LOGGED:
            return
        _REFUSALS_LOGGED.add(text)
    logger.warning(
        "LDAPS bind refused before the handshake, because its TLS context could not be built: %s. "
        "Reported once per distinct reason until a bind's context builds again.",
        text.rstrip().rstrip("."),
    )


def _sni_name(host: str) -> str | None:
    """The ``server_name`` a ClientHello to ``host`` carries, or ``None`` for none (BACKLOG #6879).

    RFC 6066 section 3 bars an IP literal and a trailing dot. The checks run on the IDNA form,
    which ssl and ``getaddrinfo`` also use, so a full-width dot counts as a dot. An IP literal
    includes a scoped IPv6 one and the legacy IPv4 spellings ``inet_aton`` reads, such as
    ``127.1``, because glibc's resolver dials those as an address. A host with no IDNA form gets
    none, and so does one longer than a DNS name's 253 bytes: that limit is the engine's choice,
    under the 255 above which OpenSSL refuses the name at the wrap. Lower case is not an RFC rule:
    it is there because some SNI routers match case-sensitively."""
    try:
        name = host.encode("idna").decode("ascii").rstrip(".")
    except UnicodeError:
        return None
    if not name or len(name) > 253 or host_address(name) is not None:
        return None
    try:
        socket.inet_aton(name)
    except (OSError, ValueError):
        return name.lower()
    return None


def _context_recovered() -> None:
    """Forget the logged refusals once a context builds, so a fault that returns is logged again."""
    if _REFUSALS_LOGGED:  # unlocked read: a stale answer costs one lock or one repeat line
        with _REFUSALS_LOCK:
            _REFUSALS_LOGGED.clear()


class NarrowedTls(ldap3.Tls):  # type: ignore[misc]  # ldap3 ships no type information
    """An ``ldap3.Tls`` whose ``wrap_socket`` uses a context the engine built and asserted.

    The constructor builds the context factory from ``validate`` and ``ca_certs_data`` and runs it
    once, so a bad context fails here. It hands the same two values to ``ldap3.Tls``, so what ldap3
    reads off this object stays true: ``validate`` decides its host name check. It takes no other
    ldap3 argument, because the engine's context would not carry one. ``ciphers=`` in particular
    reached TLS 1.2 only.

    **Not reached: a followed referral, which is why the engine follows none.** ldap3 builds a plain
    ``ldap3.Tls`` for the referred server from a few of these attributes (``strategy/base.py``,
    ``create_referral_connection``). That copy carries neither the checked CA bytes nor any of the
    narrowing, and this class does not change it. :mod:`messagefoundry.auth.ldap` turns referral
    following off and refuses a referral instead (BACKLOG #2530).
    """

    def __init__(
        self,
        *,
        validate: ssl.VerifyMode,
        ca_certs_data: str | None,
        connector: str,
        crl_file: str | None = None,
    ) -> None:
        self._context_factory = assert_ldap3_tls_suites(
            validate=validate, ca_certs_data=ca_certs_data, connector=connector, crl_file=crl_file
        )
        super().__init__(validate=validate, ca_certs_data=ca_certs_data)

    def handshake_context(self) -> ssl.SSLContext:
        """The context built and asserted at construction, from the recipe :meth:`wrap_socket`
        runs for each bind. No bind handshakes on it.

        The LDAPS revocation guard reads it (BACKLOG #2193), so the guard judges what a bind's
        handshake really loads, ``[auth].ad_tls_crl_file`` included, and never the setting, with no
        second build at start."""
        return self._context_factory.constructed

    def wrap_socket(self, connection: Any, do_handshake: bool = False) -> None:
        """ldap3's wrap step on a fresh engine context; ldap3 calls this for LDAPS and StartTLS.

        A context that cannot be built refuses the bind. Since BACKLOG #2193 that is most often an
        ``[auth].ad_tls_crl_file`` that went missing, stale or unreadable after start. ldap3 wraps
        the refusal into ``LDAPSocketOpenError`` and the engine reports that by type alone, so the
        refusal's own text, the only place that names the setting, is logged here at WARNING, once
        per distinct text, or an operator would read a lapsed CRL as a directory outage. A
        ``ValueError`` is the refusals' own type; an ``OSError``, which ``ssl.SSLError`` is, covers a
        file the account cannot read and an OpenSSL load fault."""
        try:
            context = self._context_factory()
        except (ValueError, OSError) as exc:
            _warn_context_refusal(str(exc))
            raise
        _context_recovered()
        sni = _sni_name(connection.server.host)
        wrapped = context.wrap_socket(
            connection.socket,
            server_side=False,
            do_handshake_on_connect=do_handshake,
            server_hostname=sni,
        )
        if do_handshake and self.validate in (ssl.CERT_REQUIRED, ssl.CERT_OPTIONAL):
            try:
                # The host as written, less an ASCII trailing dot, so ``localhost.`` matches a
                # leaf naming ``localhost``. Not the IDNA form: IDNA 2003 folds distinct names
                # together (sharp s to ``ss``), so a certificate for the folded name would match.
                # The raw host is not safe either, as before BACKLOG #6879: ldap3's match does
                # not split labels at a full-width dot, so ``dc1``, U+3002, ``corp.example.test``
                # matches a ``*.example.test`` wildcard that the dialled ``dc1.corp.example.test``
                # would not. Not built: refusing a non-ASCII ``ad_server`` at settings load, so
                # the dial, the SNI and this check all use one name.
                check_hostname(wrapped, connection.server.host.rstrip("."), self.valid_names)
            except BaseException:
                # ssl took the socket over, so ``connection.socket`` holds a detached one and
                # ``wrapped`` is reachable only through the error's traceback: close it here
                # (``_close_without_sending``). A close fault must not replace the refusal, so it
                # is logged and dropped, as ssl does.
                try:
                    wrapped.close()
                except OSError as failed:
                    logger.debug(
                        "LDAPS socket close after a host name refusal: %s", type(failed).__name__
                    )
                raise
        connection.socket = wrapped
