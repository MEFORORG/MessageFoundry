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
host name check. That check is ldap3's function, called, not copied. The alternative was to patch
``ldap3.core.tls.create_default_context`` for the length of one call. That is a module global, and
``AuthService`` runs binds on worker threads, so two concurrent binds could each see the other's
patch. ``tests/test_ldap_tls.py`` pins the source of ldap3's ``wrap_socket``, so an ldap3 that
changes it goes red rather than drifting from this copy.

Imported lazily by :mod:`messagefoundry.auth.ldap`, like ldap3 itself, so a local-only deployment
never loads it.
"""

from __future__ import annotations

import ssl
from typing import Any

import ldap3
from ldap3.core.tls import check_hostname

from messagefoundry.config.tls_policy import assert_ldap3_tls_suites

__all__ = ["NarrowedTls"]


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
        self, *, validate: ssl.VerifyMode, ca_certs_data: str | None, connector: str
    ) -> None:
        self._context_factory = assert_ldap3_tls_suites(
            validate=validate, ca_certs_data=ca_certs_data, connector=connector
        )
        super().__init__(validate=validate, ca_certs_data=ca_certs_data)

    def wrap_socket(self, connection: Any, do_handshake: bool = False) -> None:
        """ldap3's wrap step on a fresh engine context; ldap3 calls this for LDAPS and StartTLS."""
        wrapped = self._context_factory().wrap_socket(
            connection.socket,
            server_side=False,
            do_handshake_on_connect=do_handshake,
            server_hostname=self.sni or None,
        )
        if do_handshake and self.validate in (ssl.CERT_REQUIRED, ssl.CERT_OPTIONAL):
            check_hostname(wrapped, connection.server.host, self.valid_names)
        connection.socket = wrapped
