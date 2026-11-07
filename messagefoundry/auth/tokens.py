# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Opaque session tokens: the client holds the secret; the store keeps only its SHA-256.

Opaque server-side tokens (not JWT) are chosen so logout, expiry, and role changes take effect
immediately — the ``sessions`` row is the source of truth and can be revoked. Only the hash is
persisted, so reading the store never exposes a usable token.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
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


#: ADR 0207: a directory account's enrolment code is 160 bits from ``secrets``, at least the 128 the
#: ADR asks, and 20 bytes is exactly 32 base32 characters, so the code carries no padding.
_ENROLMENT_CODE_BYTES = 20
_ENROLMENT_CODE_CHARS = 32
_ENROLMENT_CODE_GROUP = 4
_BASE32_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
_ENROLMENT_CODE_SEPARATORS = re.compile(r"[\s-]+")


def mint_enrolment_code() -> str:
    """A fresh enrolment code, shown as base32 in groups of four joined by hyphens so a person can
    read it aloud (ADR 0207 section 3). Store only the :func:`hash_token` of its
    :func:`normalise_enrolment_code` form; the code itself is shown once and never kept."""
    raw = base64.b32encode(secrets.token_bytes(_ENROLMENT_CODE_BYTES)).decode("ascii")
    step = _ENROLMENT_CODE_GROUP
    return "-".join(raw[i : i + step] for i in range(0, len(raw), step))


def normalise_enrolment_code(text: str) -> str | None:
    """``text`` as the canonical code a digest is made over: case folded up, spaces and hyphens
    dropped. ``None`` when what is left is not 32 base32 characters, so a malformed code is never
    hashed or compared. Never logs or echoes ``text``."""
    folded = _ENROLMENT_CODE_SEPARATORS.sub("", text).upper()
    if len(folded) != _ENROLMENT_CODE_CHARS or not set(folded) <= _BASE32_ALPHABET:
        return None
    return folded


def enrolment_code_digest(text: str) -> str | None:
    """The :func:`hash_token` digest a code is stored and checked under, or ``None`` for text that
    does not normalise to a code."""
    folded = normalise_enrolment_code(text)
    return None if folded is None else hash_token(folded)


def enrolment_code_matches(stored_digest: str | None, presented: str) -> str | None:
    """The digest of ``presented`` when it equals ``stored_digest``, compared in constant time, else
    ``None``. The one compare a binding step makes before it spends a code (ADR 0207); the spend's
    own conditional write compares again on the row it replaces."""
    digest = enrolment_code_digest(presented)
    if digest is None or stored_digest is None:
        return None
    return digest if hmac.compare_digest(stored_digest, digest) else None


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

_HEX64 = re.compile(r"[0-9a-f]{64}")


class CredentialHashSchemeError(ValueError):
    """A stored credential-id hash whose scheme this release does not know, or whose shape is
    wrong. The message never echoes the value."""


def credential_id_hash(raw_id: bytes) -> str:
    """The key a passkey with this raw credential id is stored and found under, in today's scheme."""
    return f"{CREDENTIAL_ID_HASH_SCHEME}:{hash_bytes(raw_id)}"


def credential_id_hash_scheme(stored: str) -> str:
    """The scheme a stored ``credential_id_hash`` names: a tag in :data:`CREDENTIAL_ID_HASH_SCHEMES`,
    or ``""`` for a bare pre-#3423 :func:`hash_bytes` digest, which is today's hash with no tag, so
    the rehash pass moves it by adding the tag. Anything else raises
    :class:`CredentialHashSchemeError`, so a stored marker only ever chooses among the schemes
    compiled into the release."""
    scheme, sep, digest = stored.partition(":")
    if not sep:
        if _HEX64.fullmatch(stored):
            return ""
        raise CredentialHashSchemeError("a credential-id hash carries no scheme tag")
    if scheme not in CREDENTIAL_ID_HASH_SCHEMES:
        raise CredentialHashSchemeError(
            "a credential-id hash carries a scheme tag this release does not know"
        )
    if not _HEX64.fullmatch(digest):
        raise CredentialHashSchemeError("a credential-id hash's digest is not 64 lowercase hex")
    return scheme


def credential_id_hash_is_current(stored: str) -> bool:
    """Whether a stored ``credential_id_hash`` is under today's scheme, the only key the sign-in
    looks a passkey up by (BACKLOG #3423). A bare digest the start-up rehash has not moved, an
    unknown tag and a malformed value are all ``False``: no sign-in can find that passkey."""
    try:
        return credential_id_hash_scheme(stored) == CREDENTIAL_ID_HASH_SCHEME
    except CredentialHashSchemeError:
        return False
