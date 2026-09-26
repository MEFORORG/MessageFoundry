# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The OIDC relying party's outbound TLS wiring (ADR 0142, BACKLOG #274).

This is the **wiring layer** the pure :mod:`messagefoundry.auth.oidc` package deliberately does not
contain: that package opens no socket and takes its token-endpoint opener and its JWKS ``fetch``
callable as injected arguments, precisely so the network policy lives in one reviewable place. Keeping
``ssl`` here also keeps it out of the 2,000-line ``auth/service.py``.

Trust model, mirroring ``ad_tls_ca_cert_file``:

* ``ca_cert_file`` **set** -> trust *exactly* that PEM (``ssl.create_default_context(cadata=...)``),
  pinned-only, not additive: the same semantics ``apiclient`` documents for its ``cacert``. The PEM
  is loaded from the bytes the anchor check read, never by a second open of the file (BACKLOG #1142,
  slice 2). This used to say the OS verifier would not treat a ``load_verify_locations`` cert as an
  anchor on Windows. No OS verifier runs on the plain stdlib context built here, and that claim was
  not re-measured for ``truststore``. The ``cadata=`` measurement that replaces it is stated once, at
  :func:`~messagefoundry.auth.trust_anchors.verified_anchor_cadata`.
* ``ca_cert_file`` **unset** → ``ssl.create_default_context()``, whose ``load_default_certs`` DOES
  consult the Windows machine store (CPython iterates ``('CA', 'ROOT')`` on win32 — measured: 79
  anchors on a stock domain-joined box), so a group-policy-published AD-CS enterprise root is honoured.
  The anchors are a snapshot taken when the context is built, so a root published *afterwards* needs an
  engine restart — the same characteristic every other outbound hop in the engine already has.

``truststore`` is deliberately **NOT** used here despite being a base dependency. Its ``SSLContext``
re-configures a *shared* inner context for the duration of each handshake
(``check_hostname=False`` / ``verify_mode=CERT_NONE``) and restores it when ``wrap_socket`` returns —
but ``_verify_peercerts`` reads those same two attributes off that shared context *after* the restore.
Since one opener here is shared across ``asyncio.to_thread`` workers, a concurrent login could observe
``CERT_NONE`` and skip certificate validation entirely. That is an authentication bypass on the hop
that carries the identity assertion, so the live-OS-store benefit does not come close to paying for it.

Both branches verify chain **and** hostname; there is no insecure escape here by design — the IdP hop
carries an authentication assertion, so a ``verify_tls=false`` equivalent would be an authentication
bypass, not a convenience. Redirects are never followed: an open redirect on the token endpoint would
let an IdP-adjacent attacker relocate a request carrying the client secret and the authorization code.
"""

from __future__ import annotations

import http.client
import ssl
import urllib.request
from collections.abc import Callable
from typing import Any

from messagefoundry.auth.oidc.jwks import _MAX_JWKS_BYTES
from messagefoundry.auth.trust_anchors import oidc_anchor_spec, verified_anchor_cadata
from messagefoundry.config.tls_policy import (
    harden_cipher_suites,
    harden_crl_check,
    narrow_to_approved_suites,
)
from messagefoundry.transports.bounded_read import (
    AmbiguousFramingError,
    EgressReplyError,
    read_reply_body,
    reply_framing_fault,
)

__all__ = ["build_idp_opener", "jwks_fetcher"]

#: Wall-clock bound for a single IdP HTTP round trip. Deliberately short: both legs run inside a
#: browser request, and a hung IdP must degrade the federated login, never pin a worker thread.
DEFAULT_IDP_TIMEOUT_SECONDS = 10.0


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect. Duplicated from ``transports/rest.py`` rather than imported: the house
    pattern (``pipeline/alert_sinks.py`` does the same) is to keep each subsystem's opener policy local
    rather than couple the auth path to a message-transport module."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


def build_idp_opener(
    ca_cert_file: str | None,
    *,
    pin: str | None = None,
    enforcing: bool = True,
    crl_file: str | None = None,
) -> urllib.request.OpenerDirector:
    """Build the verifying, no-redirect opener used for BOTH IdP legs (token endpoint + JWKS).

    One opener for both legs so they cannot drift onto different trust anchors. It is built once at
    wiring time and never mutated afterwards, which is what makes it safe to share across the
    ``asyncio.to_thread`` dispatch (``urllib`` openers are only unsafe under concurrent
    ``add_handler`` mutation).

    A missing or unreadable ``ca_cert_file`` raises here, at construction — federation then refuses to
    start rather than silently falling back to a wider trust set.

    #285 (ASVS 6.7.1): when ``ca_cert_file`` is set, its integrity is preflighted at this construction
    point — an optional SHA-256 ``pin`` (``[auth].oidc_tls_ca_cert_pin``) that does not match refuses
    always, and a group/world-writable DACL refuses when ``enforcing`` (``[security].enforcement``).

    BACKLOG #299: ``crl_file`` (``[auth].oidc_tls_crl_file``) turns on leaf revocation checking against
    the IdP's certificate. It is this hop's OWN knob rather than an inheritance of ``[tls].crl_file``,
    because this opener resolves no trust anchor — an instance-wide CRL never reaches the context built
    here, and reporting it as covering this handshake would be the per-hop scoping error that item
    warns about. A revoked IdP certificate matters more here than on a data hop: this is the leg that
    carries the client secret, the authorization code and the identity assertion, so accepting a
    revoked-but-unexpired IdP cert would be an authentication-material exposure.

    **One CRL file serves both legs, and a CRL that misses one leg's issuer fails that leg CLOSED
    (BACKLOG #1925).** The revocation guard reads ``VERIFY_CRL_CHECK_LEAF`` off this one context, so
    a CRL from the token leg's CA alone marks the JWKS leg checked too. That does not let the JWKS leg
    cross unchecked: OpenSSL refuses a leaf whose issuer has no CRL in the store, with ``unable to get
    certificate CRL``. Measured on CPython 3.14.6 / OpenSSL 3.5.7, and pinned by
    ``tests/test_hop_refusal_revocation.py::test_a_crl_that_misses_one_legs_issuer_fails_that_leg_closed``.
    The cost is availability: the gap shows at the first login on that leg, not at start. So
    ``crl_file`` must hold a CRL from the CA of each leg.
    """
    # Both branches are plain stdlib contexts: no shared mutable verification state, so this opener is
    # safe to share across the asyncio.to_thread workers that drive the two IdP legs. See the module
    # docstring for why truststore is not used here.
    if ca_cert_file:
        # BACKLOG #1142, slice 2: load the bytes the pin, ACL and path check just read, as cadata=.
        # cafile= here would open the file a second time, and a swap between the two reads would be
        # trusted unchecked. A non-empty cadata= makes create_default_context skip the OS store, as
        # cafile= does. An EMPTY one would load the whole OS store, because it tests cadata for
        # truth, so anchor_cadata refuses an anchor with no PEM block before it gets here. A
        # certificate inside crl_file that this store lacks refuses the build (harden_crl_check, #1890).
        cadata = verified_anchor_cadata(oidc_anchor_spec(ca_cert_file, pin), enforcing=enforcing)
        ctx = ssl.create_default_context(cadata=cadata)
    else:
        ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    # BACKLOG #299: revocation checking, loaded after the trust store is final so harden_crl_check's
    # "the CRL really landed" assertion answers for the store this handshake uses. Both branches above
    # verify, so there is no CERT_NONE arm to guard against here.
    if crl_file:
        harden_crl_check(ctx, crl_file)
    # Assert forward secrecy on the FINAL context (ASVS 12.1.2): this hop carries the client secret,
    # the authorization code and the identity assertion, so a recorded session that a future key
    # compromise could decrypt is an authentication-material exposure, not just a confidentiality one.
    narrow_to_approved_suites(ctx)  # approved AEAD default (BACKLOG #300)
    harden_cipher_suites(ctx, connector="OIDC identity provider (token + JWKS)")
    return urllib.request.build_opener(_NoRedirectHandler, urllib.request.HTTPSHandler(context=ctx))


def jwks_fetcher(
    jwks_uri: str,
    opener: urllib.request.OpenerDirector,
    *,
    timeout: float = DEFAULT_IDP_TIMEOUT_SECONDS,
) -> Callable[[], bytes]:
    """Return the zero-argument ``fetch`` callable :class:`~messagefoundry.auth.oidc.jwks.JwksCache`
    expects.

    The size bound is enforced **on the socket read**, not after the fact, so a hostile or broken IdP
    cannot make the engine buffer an unbounded body before the cache's own check runs. ``JwksCache``
    re-checks the same bound — deliberate defence in depth, since ``fetch`` is injectable.

    Errors are left as raw ``urllib``/``OSError``/``http.client.HTTPException`` exceptions: the caller
    (``auth/service.py``) maps any IdP-reachability failure onto a degraded login plus an audited
    ``auth.login_error``. Nothing here
    logs the URI's response body.
    """

    def fetch() -> bytes:
        req = urllib.request.Request(  # noqa: S310 — scheme validated https at config load
            jwks_uri, headers={"Accept": "application/json"}, method="GET"
        )
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310 — see above
            # BACKLOG #1125 (ASVS 4.2.1): refuse ambiguous length framing before reading, by the
            # rule read_bounded applies to connector replies. An HTTPException, the type
            # http.client raises for its own protocol faults, so the login that triggered the fetch
            # records an unavailable IdP. A JwksError would be retyped by claims.py as
            # ClaimsError('unknown_kid'), a token-verification reject. Logins inside the refetch
            # floor after this see the cache's throttle, as after any failed fetch.
            if reply_framing_fault(resp) is not None:
                raise http.client.HTTPException("JWKS response framed its body length ambiguously")
            # BACKLOG #1979: the strict reader under read_bounded. Not read_bounded itself, because
            # JwksCache judges the length and expects the extra byte. Refusals are retyped to
            # HTTPException for the reason above, outside the handler so nothing chains to them.
            try:
                body = read_reply_body(resp, _MAX_JWKS_BYTES + 1, connector="OIDC JWKS endpoint")
            except AmbiguousFramingError:
                failure = "JWKS response framed its body length ambiguously"
            except EgressReplyError:  # the family, so a later sibling is retyped too
                failure = "JWKS response could not be read whole"
            else:
                # The declared-length check read_bounded makes, which read_reply_body leaves to its
                # caller. Skipped past the bound, where JwksCache refuses the size itself.
                remaining = getattr(resp, "length", None)
                if len(body) > _MAX_JWKS_BYTES or not (
                    isinstance(remaining, int) and remaining > 0
                ):
                    return body
                failure = "JWKS response ended before its declared length"
            raise http.client.HTTPException(failure)

    return fetch
