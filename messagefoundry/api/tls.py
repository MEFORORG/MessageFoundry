# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""In-process API / WebSocket TLS context (WP-13a, ADR 0002).

Builds the ``ssl.SSLContext`` uvicorn terminates the engine API + ``/ws/stats`` WebSocket with, from the
``[api]`` ``tls_*`` settings. Pure stdlib ``ssl`` — no FastAPI/uvicorn import — so it is unit-testable in
isolation. The ``tls_min_version`` floor (NIST SP 800-52r2: 1.2+) is enforced via
``SSLContext.minimum_version``; an encrypted key's passphrase comes from ``MEFOR_API_TLS_KEY_PASSWORD``.
"""

from __future__ import annotations

import logging
import ssl
from pathlib import Path

from messagefoundry.auth.trust_anchors import api_client_anchor_spec, enforce_anchor
from messagefoundry.config.settings import ApiSettings
from messagefoundry.config.tls_policy import (
    harden_cipher_suites,
    harden_crl_check,
    harden_kex_groups,
    harden_verify_flags,
)

__all__ = ["build_api_ssl_context", "ensure_api_tls_material"]

log = logging.getLogger(__name__)

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
        # Opt-in revocation (#1005). NOTE THE POSITION: harden_verify_flags runs ABOVE, before the
        # CA is loaded, and this must NOT sit beside it. The CRL goes into the trust store, so
        # loading it before the CA yields a context with the check flag set and zero CRLs -- which
        # refuses EVERY client rather than skipping the check.
        if api.tls_client_crl_file:
            harden_crl_check(ctx, api.tls_client_crl_file)
    return ctx


#: Filenames for the first-run generated pair, written beside the store database (BACKLOG #1276).
#: **Why there, and the alternative rejected.** That directory is already the engine's own writable
#: state (the database and its WAL live there), it is already operator-controlled via ``--db`` /
#: ``[store].path``, and it is NOT operator-authored configuration -- which is what keeps the engine
#: out of the business of editing an operator's TOML. The rejected alternative was a new
#: ``[api].tls_generated_dir`` setting: a knob for a question with one sensible answer.
_GENERATED_CERT_NAME = "api-generated-cert.pem"
_GENERATED_KEY_NAME = "api-generated-key.pem"


def ensure_api_tls_material(api: ApiSettings, *, state_dir: Path) -> tuple[str, str] | None:
    """Return the ``(cert_path, key_path)`` the API should serve with, minting on first run.

    **The engine always serves TLS (owner ruling 2026-08-22, superseding ADR 0143's cleartext
    loopback premise).** An operator-supplied ``[api].tls_cert_file`` always wins -- this is a
    fallback BENEATH it, never a replacement -- so a site that configures its own chain sees no
    behaviour change and this function is not even consulted.

    **Returns ``None`` when a reverse proxy terminates TLS upstream** -- see the guard below.

    **Mint-once, then reuse.** The pair is written with :func:`_write_private_key`'s ``O_EXCL`` +
    ``0o600`` + Windows-DACL sequence, which REFUSES to overwrite. So a second start finds the
    files and loads them; it does not re-mint, and it cannot clobber a key.

    **The generated certificate is a PLACEHOLDER TO BE REPLACED, not an endorsed production
    terminator.** It is self-signed, so it carries no chain of trust: strictly better than
    cleartext, strictly worse than an operator-supplied chain. A browser reaching the console gets
    a trust interstitial until it is imported (``docs/TRAY.md`` documents that import).

    **NOT HANDLED HERE, and it is filed rather than forgotten:** nothing re-mints an EXPIRED
    generated pair. ``build_api_ssl_context`` performs no expiry check, so on day 366 the engine
    would serve an expired certificate every client rejects. The rotation shape is an open decision
    on #1276; until it lands, ``CertExpiryRunner`` alarms on this path like any other served cert.
    """
    if api.tls_cert_file:  # operator-supplied material always wins
        return api.tls_cert_file, api.tls_key_file or ""

    # A DECLARED UPSTREAM TERMINATOR IS NOT AN UNPROTECTED HOP, AND MINTING HERE WOULD BREAK IT.
    # `tls_terminated_upstream` (+ trusted_proxies) says a reverse proxy terminates TLS in FRONT of
    # the engine and speaks plaintext to it. Serving HTTPS underneath that proxy does not harden the
    # deployment -- it breaks the proxy's own hop. "Always serves TLS" means the engine never leaves
    # a hop unprotected, NOT that it terminates TLS in every topology.
    if api.tls_terminated_upstream:
        return None

    cert_path = state_dir / _GENERATED_CERT_NAME
    key_path = state_dir / _GENERATED_KEY_NAME
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)

    from messagefoundry import pki
    from messagefoundry.__main__ import _write_private_key

    state_dir.mkdir(parents=True, exist_ok=True)
    # 365 days, inheriting the `cert self-signed` CLI default rather than inventing a second
    # lifetime for the same primitive.
    cert_pem, key_pem = pki.make_self_signed(api.host, [], 365)
    _write_private_key(key_path, key_pem)
    cert_path.write_bytes(cert_pem)
    log.warning(
        "no [api].tls_cert_file configured — minted a SELF-SIGNED certificate for %s at %s. It has "
        "no chain of trust and is a PLACEHOLDER: browsers will show a trust interstitial until it "
        "is imported, and it should be replaced with an operator-supplied chain.",
        api.host,
        cert_path,
    )
    return str(cert_path), str(key_path)
