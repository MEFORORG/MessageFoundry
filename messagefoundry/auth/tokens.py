# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Opaque session tokens: the client holds the secret; the store keeps only its SHA-256.

Opaque server-side tokens (not JWT) are chosen so logout, expiry, and role changes take effect
immediately — the ``sessions`` row is the source of truth and can be revoked. Only the hash is
persisted, so reading the store never exposes a usable token.
"""

from __future__ import annotations

import hashlib
import re
import secrets

#: Bytes of entropy per token (urlsafe-base64 encoded to ~43 chars).
_TOKEN_BYTES = 32


def mint_token() -> str:
    """Return a fresh, unguessable token to hand to the client (store only its :func:`hash_token`)."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def hash_token(token: str) -> str:
    """Hash a token for storage/lookup. Plain SHA-256 is sufficient: tokens are high-entropy secrets."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_bytes(data: bytes) -> str:
    """SHA-256 hex of raw bytes — the WebAuthn credential-id digest key (ADR 0068 §4: ids may be up
    to 1023 raw bytes, unboundable as an index key, so the store keys on this fixed-width digest —
    the same shape as :func:`hash_token` for session tokens)."""
    return hashlib.sha256(data).hexdigest()


#: The scheme tag every ``webauthn_credentials.credential_id_hash`` this release WRITES carries
#: (BACKLOG #3423, ASVS 11.2.2): SHA-256 hex of the raw credential id, as :func:`hash_bytes` gives.
#: Sign-in finds a passkey only by this value, so a release that changes the hash adds a new tag
#: and :meth:`~messagefoundry.auth.service.AuthService.rehash_webauthn_credentials` moves every
#: row to it from the raw id stored beside it. Compiled in, never a setting.
CREDENTIAL_ID_HASH_SCHEME = "wc1"

#: Every tag this release can read. The rehash pass refuses a stored value with any other tag.
CREDENTIAL_ID_HASH_SCHEMES = frozenset({CREDENTIAL_ID_HASH_SCHEME})

#: What :func:`credential_id_hash_scheme` returns for a value with no tag: the bare
#: :func:`hash_bytes` digest every release before BACKLOG #3423 wrote. It is today's hash, so the
#: rehash pass moves such a row by adding the tag.
UNTAGGED_CREDENTIAL_ID_HASH = ""

_HEX64 = re.compile(r"[0-9a-f]{64}")


class CredentialHashSchemeError(ValueError):
    """A stored credential-id hash whose scheme this release does not know, or whose shape is
    wrong. The message never echoes the value."""


def credential_id_hash(raw_id: bytes) -> str:
    """The key a passkey with this raw credential id is stored and found under, in today's scheme."""
    return f"{CREDENTIAL_ID_HASH_SCHEME}:{hash_bytes(raw_id)}"


def credential_id_hash_scheme(stored: str) -> str:
    """The scheme a stored ``credential_id_hash`` names: a tag in :data:`CREDENTIAL_ID_HASH_SCHEMES`,
    or :data:`UNTAGGED_CREDENTIAL_ID_HASH` for a bare pre-#3423 digest. Anything else raises
    :class:`CredentialHashSchemeError`, so a stored marker only ever chooses among the schemes
    compiled into the release."""
    scheme, sep, digest = stored.partition(":")
    if not sep:
        if _HEX64.fullmatch(stored):
            return UNTAGGED_CREDENTIAL_ID_HASH
        raise CredentialHashSchemeError("a credential-id hash carries no scheme tag")
    if scheme not in CREDENTIAL_ID_HASH_SCHEMES:
        raise CredentialHashSchemeError(
            "a credential-id hash carries a scheme tag this release does not know"
        )
    if not _HEX64.fullmatch(digest):
        raise CredentialHashSchemeError("a credential-id hash's digest is not 64 lowercase hex")
    return scheme
