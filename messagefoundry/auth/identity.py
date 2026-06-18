# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The resolved identity of an authenticated caller, plus the auth-provider enum.

An :class:`Identity` is built once per request from the session's user and carries the roles already
flattened to a permission set, so the API authorization dependencies can answer ``has(permission)``
without touching the store.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from messagefoundry.auth.permissions import Permission, Role, permissions_for_roles


class AuthProvider(str, Enum):
    """How a user authenticates. ``local`` users carry a password hash; ``ad`` users bind to AD."""

    LOCAL = "local"
    AD = "ad"


@dataclass(frozen=True, slots=True)
class Identity:
    """An authenticated user with roles resolved to a flat, deny-by-default permission set."""

    user_id: str
    username: str
    auth_provider: AuthProvider
    roles: frozenset[Role]
    permissions: frozenset[Permission]
    must_change_password: bool = False
    #: Per-channel RBAC scope: connections this user's *operational* permissions apply to. ``None``
    #: = all channels (the default / Administrators). See docs/security/PHASE-8C-RBAC.md.
    allowed_channels: frozenset[str] | None = None

    @classmethod
    def build(
        cls,
        *,
        user_id: str,
        username: str,
        auth_provider: AuthProvider,
        roles: Iterable[Role],
        must_change_password: bool = False,
        allowed_channels: frozenset[str] | None = None,
    ) -> Identity:
        """Construct an identity, resolving ``roles`` to their union of permissions."""
        role_set = frozenset(roles)
        return cls(
            user_id=user_id,
            username=username,
            auth_provider=auth_provider,
            roles=role_set,
            permissions=permissions_for_roles(role_set),
            must_change_password=must_change_password,
            allowed_channels=allowed_channels,
        )

    def has(self, permission: Permission) -> bool:
        """True iff one of this identity's roles grants ``permission``."""
        return permission in self.permissions

    def can_access_channel(self, channel_id: str | None) -> bool:
        """True iff the user's per-channel scope permits ``channel_id`` (``None`` scope = all)."""
        if self.allowed_channels is None:
            return True
        return channel_id is not None and channel_id in self.allowed_channels
