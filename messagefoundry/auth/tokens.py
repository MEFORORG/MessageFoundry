"""Opaque session tokens: the client holds the secret; the store keeps only its SHA-256.

Opaque server-side tokens (not JWT) are chosen so logout, expiry, and role changes take effect
immediately — the ``sessions`` row is the source of truth and can be revoked. Only the hash is
persisted, so reading the store never exposes a usable token.
"""

from __future__ import annotations

import hashlib
import secrets

#: Bytes of entropy per token (urlsafe-base64 encoded to ~43 chars).
_TOKEN_BYTES = 32


def mint_token() -> str:
    """Return a fresh, unguessable token to hand to the client (store only its :func:`hash_token`)."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def hash_token(token: str) -> str:
    """Hash a token for storage/lookup. Plain SHA-256 is sufficient: tokens are high-entropy secrets."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
