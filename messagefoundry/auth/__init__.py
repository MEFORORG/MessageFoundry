"""Authentication & RBAC core — provider-agnostic, with no FastAPI/Qt imports.

Pure building blocks the API layer composes: the permission catalog and fixed built-in roles
(:mod:`~messagefoundry.auth.permissions`), the resolved :class:`~messagefoundry.auth.identity.Identity`,
argon2id password hashing, the password/lockout policy, and opaque session tokens. Like ``store``,
this package is importable by ``api`` but never imports it (one-way dependency direction).
"""

from __future__ import annotations

from messagefoundry.auth.identity import AuthProvider, Identity
from messagefoundry.auth.passwords import hash_password, needs_rehash, verify_password
from messagefoundry.auth.permissions import (
    BUILTIN_ROLE_PERMISSIONS,
    ROLE_METADATA,
    Permission,
    Role,
    permissions_for_roles,
)
from messagefoundry.auth.policy import PasswordPolicy
from messagefoundry.auth.tokens import hash_token, mint_token

__all__ = [
    "AuthProvider",
    "Identity",
    "Permission",
    "Role",
    "BUILTIN_ROLE_PERMISSIONS",
    "ROLE_METADATA",
    "permissions_for_roles",
    "PasswordPolicy",
    "hash_password",
    "verify_password",
    "needs_rehash",
    "mint_token",
    "hash_token",
]
