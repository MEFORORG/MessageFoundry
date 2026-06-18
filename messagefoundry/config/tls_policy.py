# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shared TLS key-exchange policy (ASVS 11.6.2, WP-L3-10 code half).

Pure stdlib ``ssl`` helpers, importable by ``api/`` and ``transports/`` (and the ``config`` settings
validator) without crossing the engine's one-way dependency boundaries. Two controls:

* :func:`validate_tls_ciphers` — reject an operator ``tls_ciphers`` string that would admit a
  non-forward-secret (non-ECDHE/DHE) key exchange, so a misconfiguration cannot widen the suite below
  policy. Run from the ``[api].tls_ciphers`` settings validator, so a bad value fails loud at load.
* :func:`harden_kex_groups` — pin the approved ECDHE groups on a built context where the runtime
  supports it (``SSLContext.set_groups``, Python 3.13+); on older interpreters OpenSSL already leads
  with these groups, so it is a best-effort no-op rather than a downgrade.
"""

from __future__ import annotations

import logging
import ssl
from collections.abc import Mapping

logger = logging.getLogger(__name__)

__all__ = ["APPROVED_KEX_GROUPS", "harden_kex_groups", "validate_tls_ciphers"]

#: Approved forward-secret key-exchange groups in preference order (X25519 first). These are the modern
#: NIST/FIPS-permitted ECDHE curves; the string is the OpenSSL group list passed to ``set_groups``.
APPROVED_KEX_GROUPS = "X25519:secp384r1:secp256r1"


def harden_kex_groups(ctx: ssl.SSLContext) -> None:
    """Best-effort pin ``ctx`` to :data:`APPROVED_KEX_GROUPS`.

    Uses ``SSLContext.set_groups`` where available (Python 3.13+). On older interpreters there is no
    public API to pin groups and OpenSSL's defaults already lead with X25519/P-256/P-384, so this is a
    deliberate no-op rather than a weakening. A runtime that rejects the group list (an unusual OpenSSL
    build) is logged and left at its secure defaults."""
    set_groups = getattr(ctx, "set_groups", None)
    if set_groups is None:
        return
    try:
        set_groups(APPROVED_KEX_GROUPS)
    except (
        ssl.SSLError,
        ValueError,
    ) as exc:  # pragma: no cover - depends on the linked OpenSSL build
        logger.warning("Could not pin TLS key-exchange groups %r: %s", APPROVED_KEX_GROUPS, exc)


def validate_tls_ciphers(value: str) -> str:
    """Validate an operator OpenSSL cipher string, rejecting non-forward-secret key exchange.

    Returns ``value`` unchanged when it parses and every resolved TLS 1.2 suite uses (EC)DHE (TLS 1.3
    suites are inherently ECDHE + AEAD). Raises ``ValueError`` — surfaced as a config-load error — for
    an unparseable string or one that would admit a static-RSA/DH key exchange, closing the 11.6.2 gap
    that a misconfigured ``tls_ciphers`` could widen the key exchange below policy."""
    probe = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        probe.set_ciphers(value)
    except ssl.SSLError as exc:
        raise ValueError(f"tls_ciphers is not a valid OpenSSL cipher string: {exc}") from exc
    non_fs = sorted(
        {str(c.get("name", "?")) for c in probe.get_ciphers() if not _is_forward_secret(c)}
    )
    if non_fs:
        raise ValueError(
            "tls_ciphers must resolve to forward-secret (EC)DHE suites only (ASVS 11.6.2); "
            f"these admit a non-forward-secret key exchange: {', '.join(non_fs)}"
        )
    return value


def _is_forward_secret(cipher: Mapping[str, object]) -> bool:
    """Whether a ``SSLContext.get_ciphers()`` entry uses an (EC)DHE — forward-secret — key exchange."""
    name = str(cipher.get("name", ""))
    # TLS 1.3 suite names (TLS_AES_*, TLS_CHACHA20_*) are always ECDHE and cannot be configured down.
    if name.startswith("TLS_") or cipher.get("protocol") == "TLSv1.3":
        return True
    if name.startswith(("ECDHE", "DHE")):
        return True
    # Fall back to the human description's Kx token (stable across CPython versions).
    desc = str(cipher.get("description", ""))
    return "Kx=ECDH" in desc or "Kx=DH" in desc
