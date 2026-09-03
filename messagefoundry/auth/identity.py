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


class AuthProvider(str, Enum):  # noqa: UP042
    """How a user authenticates. ``local`` users carry a password hash; ``ad`` users bind to AD."""

    LOCAL = "local"
    AD = "ad"


#: The explicit all-channels grant token, as it is stored in ``users.channel_scope`` (the JSON list
#: ``["*"]``) and as the admin setter accepts it. BACKLOG #1152 (ASVS 8.2.2) retired the older
#: encoding where an ABSENT scope meant every channel: all-channels is now a grant somebody typed,
#: and saying nothing denies. The token is not new vocabulary — the AD-group-to-channel map has
#: always stored ``*`` for a wildcard row (``ad_group_channels.channel``), and this reuses it so one
#: string means one thing across the whole scope surface.
ALL_CHANNELS = "*"


@dataclass(frozen=True, slots=True)
class Identity:
    """An authenticated user with roles resolved to a flat, deny-by-default permission set."""

    user_id: str
    username: str
    auth_provider: AuthProvider
    roles: frozenset[Role]
    permissions: frozenset[Permission]
    must_change_password: bool = False
    #: Per-channel RBAC scope: connections this user's *operational* permissions apply to. A
    #: frozenset restricts to exactly those connection ids; ``None`` is unrestricted. Note ``None``
    #: and an EMPTY frozenset are not the same value -- None is every channel, and the empty set is
    #: no channel at all. The first draft of this comment said "empty frozenset means every
    #: channel", which is the inverse; it was caught by re-reading the annotation.
    #:
    #: **THE DEFAULT DENIES (BACKLOG #1152, ASVS 8.2.2), and it used to be ``None``.** An identity
    #: built without a scope now reaches no channel, so a rule written against this axis protects a
    #: default install instead of resting on a premise that was false the moment nobody typed
    #: anything. Unrestricted is still reachable and is now always deliberate: the ADMINISTRATOR
    #: role, or the :data:`ALL_CHANNELS` grant in the stored scope, both resolved by
    #: ``auth.service._allowed_channels``. A caller constructing an ``Identity`` DIRECTLY (rather
    #: than through the resolver) and wanting the whole estate must pass ``allowed_channels=None``
    #: and say why -- ``api.security._SYSTEM_IDENTITY`` is the one such site in the engine.
    #:
    #: BACKLOG #1151 (ASVS 8.1.1): this used to end "See docs/security/PHASE-8C-RBAC.md", which a
    #: reader of the public repository CANNOT REACH -- `docs/security/` is gitignored here, so
    #: `git ls-files docs/security` returns zero and the directory is absent from a fresh checkout.
    #: That is a standing decision, not an oversight, which is exactly why the pointer had to go: a
    #: dangling reference to a security document is worse than no reference, because it tells the
    #: reader the rule is written down somewhere they can look. THE RULE ITSELF IS STATED ABOVE.
    allowed_channels: frozenset[str] | None = frozenset()

    @classmethod
    def build(
        cls,
        *,
        user_id: str,
        username: str,
        auth_provider: AuthProvider,
        roles: Iterable[Role],
        must_change_password: bool = False,
        allowed_channels: frozenset[str] | None = frozenset(),
        extra_permissions: Iterable[Permission] = (),
    ) -> Identity:
        """Construct an identity, resolving ``roles`` to their union of permissions.

        ``allowed_channels`` defaults to the EMPTY set, not ``None`` — see the field's own note. Omit
        it and the identity reaches no channel; pass ``None`` to mean the whole estate.

        ``extra_permissions`` are unioned on top of the built-in role permissions — the additive
        custom-role overlay (ADR 0045): a user's effective set is *built-in-role ∪ custom-role*
        permissions. The flat ``permissions`` set is what every authorization check consults, so where
        a permission came from is invisible downstream.
        """
        role_set = frozenset(roles)
        permissions = permissions_for_roles(role_set) | frozenset(extra_permissions)
        return cls(
            user_id=user_id,
            username=username,
            auth_provider=auth_provider,
            roles=role_set,
            permissions=permissions,
            must_change_password=must_change_password,
            allowed_channels=allowed_channels,
        )

    def has(self, permission: Permission) -> bool:
        """True iff one of this identity's roles grants ``permission``."""
        return permission in self.permissions

    def can_access_channel(self, channel_id: str | None) -> bool:
        """True iff the user's per-channel scope permits ``channel_id``.

        A ``None`` scope is the whole estate; any frozenset permits exactly its members, so the
        empty set — the default since BACKLOG #1152 — permits nothing."""
        if self.allowed_channels is None:
            return True
        return channel_id is not None and channel_id in self.allowed_channels

    @property
    def has_no_channels(self) -> bool:
        """True iff this identity is scoped to zero connections — the unprovisioned-operator state.

        The console asks this to explain an empty page rather than let it read as broken RBAC on a
        fresh install (BACKLOG #1152). It is a display question, never an authorization one: every
        gate calls :meth:`can_access_channel`, which denies on exactly this state anyway."""
        return self.allowed_channels is not None and not self.allowed_channels
