# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The OIDC relying party's outbound TLS wiring (ADR 0142, BACKLOG #274).

This is the **wiring layer** the pure :mod:`messagefoundry.auth.oidc` package deliberately does not
contain: that package opens no socket and takes its token-endpoint opener and its JWKS ``fetch``
callable as injected arguments, precisely so the network policy lives in one reviewable place. Keeping
``ssl`` here also keeps it out of the 2,000-line ``auth/service.py``.

Trust model, mirroring ``ad_tls_ca_cert_file``:

* ``ca_cert_file`` **set** → trust *exactly* that PEM (``ssl.create_default_context(cafile=…)``). The
  OS verifier will not treat a ``load_verify_locations`` cert as an anchor on Windows, so pinning is
  pinned-only, not additive — the same semantics ``apiclient`` documents for its ``cacert``.
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

import ssl
import urllib.request
from collections.abc import Callable
from typing import Any

from messagefoundry.auth.oidc.jwks import _MAX_JWKS_BYTES
from messagefoundry.auth.trust_anchors import AnchorSpec, enforce_anchor

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
    """
    if ca_cert_file:
        enforce_anchor(
            AnchorSpec("oidc", "[auth].oidc_tls_ca_cert_file", ca_cert_file, pin),
            enforcing=enforcing,
        )
    # Both branches are plain stdlib contexts: no shared mutable verification state, so this opener is
    # safe to share across the asyncio.to_thread workers that drive the two IdP legs. See the module
    # docstring for why truststore is not used here.
    ctx = (
        ssl.create_default_context(cafile=ca_cert_file)
        if ca_cert_file
        else ssl.create_default_context()
    )
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
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

    Errors are left as raw ``urllib``/``OSError`` exceptions: the caller (``auth/service.py``) maps any
    IdP-reachability failure onto a degraded login plus an audited ``auth.login_error``. Nothing here
    logs the URI's response body.
    """

    def fetch() -> bytes:
        req = urllib.request.Request(  # noqa: S310 — scheme validated https at config load
            jwks_uri, headers={"Accept": "application/json"}, method="GET"
        )
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310 — see above
            return bytes(resp.read(_MAX_JWKS_BYTES + 1))

    return fetch
