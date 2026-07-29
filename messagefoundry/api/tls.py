# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""In-process API / WebSocket TLS context (WP-13a, ADR 0002).

Builds the ``ssl.SSLContext`` uvicorn terminates the engine API + ``/ws/stats`` WebSocket with, from the
``[api]`` ``tls_*`` settings. Pure stdlib ``ssl`` — no FastAPI/uvicorn import — so it is unit-testable in
isolation. The ``tls_min_version`` floor (NIST SP 800-52r2: 1.2+) is enforced via
``SSLContext.minimum_version``; an encrypted key's passphrase comes from ``MEFOR_API_TLS_KEY_PASSWORD``.
"""

from __future__ import annotations

import ssl

from messagefoundry.auth.trust_anchors import api_client_anchor_spec, enforce_anchor
from messagefoundry.config.settings import ApiSettings
from messagefoundry.config.tls_policy import (
    harden_cipher_suites,
    harden_kex_groups,
    harden_verify_flags,
)

__all__ = ["build_api_ssl_context"]

# Map the validated tls_min_version floor to the SSLContext minimum (TLS < 1.2 is never allowed).
_MIN_VERSION = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}


def build_api_ssl_context(api: ApiSettings, *, enforcing: bool = True) -> ssl.SSLContext:
    """Build the server ``SSLContext`` for the API listener from ``[api].tls_*``.

    Requires ``api.tls_cert_file`` (the caller checks ``api.tls_enabled`` first). The private key may be
    embedded in the cert PEM (``tls_key_file`` optional). mTLS is **opt-in**: when ``tls_client_ca_file``
    is set, a client cert is **required** and verified against it (console mutual auth); otherwise no
    client auth (the default).

    #285 (ASVS 6.7.1): when ``tls_client_ca_file`` is set, the client-CA trust anchor is preflighted at
    this construction point — an optional SHA-256 pin (``[api].tls_client_ca_pin``) mismatch refuses
    always, and a group/world-writable DACL refuses when ``enforcing`` (``[security].enforcement``)."""
    if not api.tls_cert_file:
        raise ValueError("build_api_ssl_context requires [api].tls_cert_file")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = _MIN_VERSION[api.tls_min_version]
    # An encrypted key with no passphrase must fail deterministically, not fall back to OpenSSL's blocking
    # TTY prompt (no TTY under a service account / in a container). The empty-bytes callback is never
    # invoked for an unencrypted key (prior behavior preserved) and raises ssl.SSLError otherwise.
    pw_arg = api.tls_key_password if api.tls_key_password is not None else (lambda: b"")
    ctx.load_cert_chain(
        certfile=api.tls_cert_file,
        keyfile=api.tls_key_file,
        password=pw_arg,
    )
    if api.tls_ciphers:
        ctx.set_ciphers(api.tls_ciphers)
    harden_kex_groups(ctx)  # pin approved ECDHE groups where the runtime supports it (ASVS 11.6.2)
    harden_cipher_suites(ctx, connector="API/UI listener")  # assert forward secrecy (ASVS 12.1.2)
    harden_verify_flags(ctx)  # strict RFC 5280 cert validation (ASVS 12.1.4)
    client_ca = api_client_anchor_spec(api)
    if client_ca is not None:
        enforce_anchor(client_ca, enforcing=enforcing)  # #285: pin + owner-only-DACL preflight
        ctx.load_verify_locations(cafile=api.tls_client_ca_file)
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx
