# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""In-process API / WebSocket TLS context (WP-13a, ADR 0002).

Builds the ``ssl.SSLContext`` uvicorn terminates the engine API + ``/ws/stats`` WebSocket with, from the
``[api]`` ``tls_*`` settings. Pure stdlib ``ssl`` — no FastAPI/uvicorn import — so it is unit-testable in
isolation. The ``tls_min_version`` floor (NIST SP 800-52r2: 1.2+) is enforced via
``SSLContext.minimum_version``; an encrypted key's passphrase comes from ``MEFOR_API_TLS_KEY_PASSWORD``.
"""

from __future__ import annotations

import logging
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from messagefoundry.auth.trust_anchors import api_client_anchor_spec, enforce_anchor
from messagefoundry.config.settings import ApiSettings
from messagefoundry.config.tls_policy import (
    harden_cipher_suites,
    harden_crl_check,
    harden_kex_groups,
    harden_verify_flags,
)

__all__ = [
    "ApiTlsPlan",
    "ApiTlsSource",
    "api_tls_source",
    "build_api_ssl_context",
    "ensure_api_tls_material",
    "generated_state_dir",
    "plan_api_tls_material",
]

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


def _generated_pair(state_dir: Path) -> tuple[Path, Path]:
    """The ``(cert, key)`` paths of the first-run generated pair. The only place they are spelled."""
    return state_dir / _GENERATED_CERT_NAME, state_dir / _GENERATED_KEY_NAME


def generated_state_dir(store_path: str) -> Path:
    """Where the engine keeps its own writable state: the directory holding the store database.

    Named here rather than spelled at each call site, because it is the rule a CLIENT must not have
    to know -- and it was already written twice (the serve path and the ``cert inventory`` reporter)
    before it had a name.
    """
    return Path(store_path).resolve().parent


#: Where the material the API bind serves with comes from. ``upstream`` is the one source that is not
#: material at all -- a declared reverse proxy terminates TLS in front and the engine serves plaintext.
ApiTlsSource = Literal["operator", "generated", "upstream"]


def api_tls_source(*, cert_file: str | None, tls_terminated_upstream: bool) -> ApiTlsSource:
    """The ORDER: an operator chain wins, a declared upstream terminator mints nothing, else generated.

    Takes the two settings rather than an :class:`ApiSettings`, so a caller that cannot afford this
    module's imports -- the tray reads an untrusted, possibly-malformed service TOML and must degrade
    rather than raise (ADR 0113 layering) -- can share the ordering without sharing the machinery.
    """
    if cert_file:
        return "operator"
    return "upstream" if tls_terminated_upstream else "generated"


@dataclass(frozen=True)
class ApiTlsPlan:
    """What the API bind **will** serve with, decided without reading or writing a single file.

    This is the branch order of :func:`ensure_api_tls_material` lifted out so a caller that must not
    mint can still answer the two questions a CLIENT has: *which scheme does this engine speak*, and
    *which certificate will it present*. Both were previously derivable only by re-implementing the
    predicate, and each re-implementation got it wrong in its own way -- keying the scheme on
    ``[api].tls_cert_file`` alone reads the SHIPPED DEFAULT as cleartext (BACKLOG #1126), and a
    client with no idea where the generated pair lands cannot trust it at all (BACKLOG #1695).

    **THE ORDERING IS NOT DECLARED ONCE IN THIS REPOSITORY, and saying so would be the
    false-premise documentation that let the first copy drift.** ``tray/config.py``'s
    ``engine_serves_https`` spells it a second time, over a raw TOML dict, and that copy stays: the
    tray is stdlib-only by ADR 0113, and importing this module would pull pydantic and the settings
    package into a tray icon's startup for one boolean. :func:`api_tls_source` exists so the order
    is at least *callable* without the machinery -- it takes the two settings, not an
    :class:`ApiSettings` -- and converging the tray onto it is unfiled follow-up work.
    """

    source: ApiTlsSource
    #: The certificate the bind will present, **whether or not it exists yet** -- for ``generated``
    #: this is the path the engine mints to on its first run. ``None`` only for ``upstream``.
    cert_file: str | None
    key_file: str | None

    @property
    def scheme(self) -> Literal["http", "https"]:
        """The scheme the engine's OWN bind serves.

        ``http`` only for a DECLARED upstream terminator, which is not a weaker posture: the proxy
        holds the protected hop and the engine speaks plaintext behind it. A client that hardcodes
        https breaks exactly that topology, which is why this is reported rather than assumed.
        """
        return "http" if self.source == "upstream" else "https"

    def material(self) -> tuple[str, str | None] | None:
        """The pair in :func:`ensure_api_tls_material`'s shape, or ``None`` for an upstream proxy."""
        return None if self.cert_file is None else (self.cert_file, self.key_file)


def plan_api_tls_material(api: ApiSettings, *, state_dir: Path) -> ApiTlsPlan:
    """Decide the API bind's TLS posture **without touching the disk** -- see :class:`ApiTlsPlan`.

    Pure: it neither mints, reads, nor stats anything, so it is safe on a read-only path (the
    ``cert inventory`` reporter) and safe to call before the engine has ever run.
    :func:`ensure_api_tls_material` consumes it, so the engine's own material is decided once.
    """
    source = api_tls_source(
        cert_file=api.tls_cert_file, tls_terminated_upstream=api.tls_terminated_upstream
    )
    if source == "operator":
        # Pass tls_key_file through UNCHANGED, None included -- see ensure_api_tls_material.
        return ApiTlsPlan(source, api.tls_cert_file, api.tls_key_file)
    if source == "upstream":
        return ApiTlsPlan(source, None, None)
    cert_path, key_path = _generated_pair(state_dir)
    return ApiTlsPlan(source, str(cert_path), str(key_path))


def ensure_api_tls_material(api: ApiSettings, *, state_dir: Path) -> tuple[str, str | None] | None:
    """Return the ``(cert_path, key_path)`` the API should serve with, minting on first run.

    **``key_path`` is ``None`` when the operator embedded the key in the cert PEM.** That is a
    supported configuration (``[api].tls_key_file`` is optional -- see :class:`ApiSettings` and
    :func:`build_api_ssl_context`), and the ``None`` must survive all the way to
    ``ssl.load_cert_chain(keyfile=...)``, which reads a combined PEM only when keyfile is ``None``.
    Substituting ``""`` for it raises ``OSError: [Errno 22] Invalid argument`` instead, so an
    operator with a combined PEM could not start the engine at all. A minted pair is always two
    files, so that branch returns a real path.

    **The engine always serves TLS (owner ruling 2026-08-22, superseding ADR 0143's cleartext
    loopback premise).** An operator-supplied ``[api].tls_cert_file`` always wins -- this is a
    fallback BENEATH it, never a replacement -- so a site that configures its own chain sees no
    behaviour change and this function is not even consulted.

    **Returns ``None`` when a reverse proxy terminates TLS upstream.** Which of the three postures
    applies is :func:`plan_api_tls_material`'s decision, not this function's -- this one adds only
    the minting, so a read-only caller can ask the same question without writing a key.

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
    # The branch order lives in plan_api_tls_material, so the read-only reporter and the minting
    # path cannot disagree about which certificate the bind presents. Two of the three branches
    # need no disk at all: an operator's material is passed through UNCHANGED (tls_key_file's None
    # included -- see the key_path note above), and a DECLARED UPSTREAM TERMINATOR IS NOT AN
    # UNPROTECTED HOP, so minting there would break the proxy's own plaintext hop rather than
    # harden anything. "Always serves TLS" means the engine never leaves a hop unprotected, NOT
    # that it terminates TLS in every topology.
    plan = plan_api_tls_material(api, state_dir=state_dir)
    if plan.source != "generated":
        return plan.material()

    cert_path, key_path = _generated_pair(state_dir)
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
