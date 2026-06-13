"""argon2id password hashing (argon2-cffi) for *local* users.

AD users never reach here — they authenticate by binding to the directory. The hash string embeds
its own salt and cost parameters, so it is self-contained and safe to store in the ``users`` table.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# argon2id cost parameters, pinned EXPLICITLY rather than relying on argon2-cffi's library defaults
# (ASVS 11.4.2). Pinning means a library upgrade can't silently weaken (or change) the work factor,
# and ``needs_rehash`` transparently upgrades any stored hash that predates a future bump. These
# values meet/exceed OWASP guidance for argon2id (memory ≥ 19 MiB; here 64 MiB, t=3, p=4) and a unit
# test asserts them so a drift is caught in CI.
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


def verify_password(stored_hash: str, password: str) -> bool:
    """True iff ``password`` matches ``stored_hash``. Never raises on a bad password or malformed hash."""
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
