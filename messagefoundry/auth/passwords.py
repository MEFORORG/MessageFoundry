# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""argon2id password hashing (argon2-cffi) for *local* users.

AD users never reach here. Directory password sign-in is retired, so they sign in with Windows SSO
(Kerberos) or OIDC. A Kerberos session steps up with the user's password, which a re-bind to the
directory checks (``AuthService._reauth_ad``), never a stored hash. An OIDC session steps up at the
identity provider and sends no password to the engine.

The hash string embeds its own salt and cost parameters, so it is self-contained and safe to store
in the ``users`` table.
"""

from __future__ import annotations

import functools
import logging

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from messagefoundry.controlchars import has_lone_surrogate

_log = logging.getLogger(__name__)

# argon2id cost parameters (ASVS 11.4.2, 11.4.4). These are RFC 9106 section 4's SECOND recommended
# option, and argon2-cffi exposes the same tuple as ``argon2.profiles.RFC_9106_LOW_MEMORY``. They
# meet or exceed OWASP Password Storage guidance for argon2id, whose highest listed configuration is
# m=46 MiB / t=1 / p=1 against the 64 MiB / t=3 / p=4 here.
#
# THIS COMMENT USED TO SAY THE VALUES WERE PINNED "rather than relying on argon2-cffi's library
# defaults", AND THAT WAS FALSE (BACKLOG #1352). Measured against the pinned argon2-cffi 25.1.0:
# ``PasswordHasher()`` with no arguments yields t=3, m=65536, p=4, hash_len=32, salt_len=16 -- all
# five byte-identical to the constants below. A reader auditing the work factor would have taken the
# old sentence as evidence that someone compared this profile against the library's and chose
# differently, and no such choice is recorded anywhere. Asserting a deliberation the artifact cannot
# evidence is a compensating control resting on a false premise (CLAUDE.md section 11, SDS-3.7).
#
# What the pin DOES do is real, and is the reason to keep it: naming the five values explicitly means
# a future argon2-cffi that moves its defaults cannot move this engine's work factor with it, and
# ``tests/test_asvs_phase0.py`` fails if it drifts. ``needs_rehash`` then upgrades any stored hash
# that predates a deliberate bump, on the owner's next login. That the numbers currently COINCIDE
# with the library's is a fact about this version, not a property the pin depends on.
#
# What is still unrecorded, and is the open half of #1352: the reference hardware, the measured
# per-verify cost, and the login concurrency this must sustain. Note the multiplier -- MFA recovery
# codes run one argon2id verify per configured slot (default 10, capped at 50), so a verify budget
# chosen for a single password check is not the whole cost.
_ARGON2_TIME_COST = 3
_ARGON2_MEMORY_COST = 65536  # KiB = 64 MiB
_ARGON2_PARALLELISM = 4
_ARGON2_HASH_LEN = 32
_ARGON2_SALT_LEN = 16

# One shared, stateless hasher with the pinned argon2id parameters above.
_hasher = PasswordHasher(
    time_cost=_ARGON2_TIME_COST,
    memory_cost=_ARGON2_MEMORY_COST,
    parallelism=_ARGON2_PARALLELISM,
    hash_len=_ARGON2_HASH_LEN,
    salt_len=_ARGON2_SALT_LEN,
)


def hash_password(password: str) -> str:
    """Return an argon2id hash (salt + parameters included) to store for a local user."""
    return _hasher.hash(password)


#: The fixed input of the constant-work verify below. Not a credential: nothing stores its hash.
_CONSTANT_WORK_INPUT = "mf-verify-constant-work"


@functools.cache
def _constant_work_hash() -> str:
    """A hash at the pinned parameters, made on first use rather than at import, so importing this
    module stays free of argon2 work. The first call pays one extra hash."""
    return _hasher.hash(_CONSTANT_WORK_INPUT)


def _spend_one_verify() -> None:
    """One argon2id verify at the pinned cost, its answer discarded.

    Callers equalize timing on the premise that each ``verify_password`` call costs one verify: at
    least the recovery-code walk, which runs every slot so the attempt's cost does not reveal which
    slot matched (ADR 0170). An input refused before the hasher runs would break that premise per
    refused slot, so the refusal pays the same work here."""
    _hasher.verify(_constant_work_hash(), _CONSTANT_WORK_INPUT)


def verify_password(stored_hash: str, password: str) -> bool:
    """True iff ``password`` matches ``stored_hash``. Never raises on a bad password or malformed hash.

    Every call does one argon2id verify's work, including the two refusals below (BACKLOG #6880)."""
    # argon2-cffi encodes the hash as ASCII and the password as UTF-8 before argon2 sees either, and
    # neither encode failure becomes one of its own exception types. Both inputs are therefore
    # screened first, so no ``UnicodeEncodeError`` is ever raised here: that exception carries the
    # whole hash or password, and would chain onto anything a failing log handler prints.
    #
    # ``hash_password`` only ever emits ASCII, so a non-ASCII stored hash, whether of a password or
    # of a recovery code, is at least one of: corruption of an unsealed row, a defect in a path that
    # writes the hash, or tampering. Where the users row is sealed, at-rest corruption fails the seal
    # before this runs. Hence a WARNING that names no single cause.
    if not stored_hash.isascii():
        _spend_one_verify()
        _log.warning("stored argon2 hash is not ASCII; treating it as a non-match")
        return False
    # A surrogate code point is the one thing strict UTF-8 refuses. It is caller input, and no stored
    # hash can match it, because ``hash_password`` cannot hash it either. At least the sign-in request
    # model refuses one with a 422 (pinned in tests/test_auth_hardening.py), so this guards any
    # caller that skips such a model.
    if has_lone_surrogate(password):
        _spend_one_verify()
        _log.debug("password does not encode as UTF-8; treating it as a non-match")
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True if ``stored_hash`` uses weaker-than-current parameters and should be upgraded on login."""
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return False
