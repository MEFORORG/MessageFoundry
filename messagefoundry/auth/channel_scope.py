# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Per-channel scope: how a stored scope reads, and what the directory does to it (ADR 0198).

Pure: no I/O, no store access. Two callers need the same answers and must never hold two copies:

* every request's scope is built by ``_allowed_channels`` in ``auth/service.py``, from
  :func:`scope_channels`;
* the AD login sync (``_sync_ad_channel_scope``) and the directory reconciler's ``plan_pass`` both
  decide a directory account's scope with :func:`decide_ad_channel_scope`. If they disagreed, a pass
  could revoke for a scope login never writes, and every later pass would revoke again, which is
  the shape of the BACKLOG #1532 loop.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.store.store import SCOPE_SOURCE_AD, SCOPE_SOURCE_MANUAL


def scope_channels(scope_json: str | None) -> frozenset[str] | None:
    """What a stored ``users.channel_scope`` reaches: a channel set, or ``None`` for every channel.

    ``_allowed_channels`` builds each request's scope from this, and :func:`decide_ad_channel_scope`
    uses it to tell whether a directory change takes access away. Sharing it means the reconciler
    cannot revoke over a difference no request ever sees. (``api/auth_routes.py`` decodes the same
    column for DISPLAY, which is a different question and not an access decision.)

    An absent scope denies (BACKLOG #1152), and so does anything malformed. :data:`ALL_CHANNELS` in
    the list is the deliberate all-channels grant. The Administrator role is not this function's
    question; the callers answer it first."""
    if scope_json is None:
        return frozenset()
    try:
        names = json.loads(scope_json)
    except (ValueError, TypeError):
        return frozenset()
    if not isinstance(names, list):
        return frozenset()
    if ALL_CHANNELS in names:
        return None
    return frozenset(str(n) for n in names)


def _narrows(before: frozenset[str] | None, after: frozenset[str] | None) -> bool:
    """Whether moving from ``before`` to ``after`` takes away at least one channel (None = all)."""
    if after is None:
        return False
    if before is None:
        return True
    return not before <= after


@dataclass(frozen=True)
class ScopeInput:
    """What the decision reads for one directory account."""

    stored_scope: str | None
    stored_source: str | None
    #: The channels the account's groups map to (``channels_for_ad_groups``). May hold
    #: :data:`ALL_CHANNELS`. Empty means no scope-mapped group matched.
    mapped: frozenset[str]
    #: Whether the account's roles include Administrator. At login these are the roles being
    #: written; the reconciler passes its TARGET roles for the same reason.
    administrator: bool


@dataclass(frozen=True)
class ScopeDecision:
    """What the directory's groups mean for one account's stored scope.

    ``write`` is whether login persists a scope. ``scope_json`` is what it persists: the JSON list,
    or ``None`` for a withdrawal to NULL. ``changes`` is whether that value differs from the stored
    one, which is login's revocation trigger. ``narrows`` is whether it takes a channel away, which is
    the reconciler's (ADR 0198). ``narrows`` implies ``write`` and ``changes``, and that implication
    is what keeps the #1532 loop closed: whatever the pass revokes for, the next login writes."""

    write: bool = False
    scope_json: str | None = None
    changes: bool = False
    narrows: bool = False
    wildcard: bool = False
    #: The specific channels a write grants, sorted. Empty for a withdrawal or a wildcard.
    channels: tuple[str, ...] = ()


#: The decision that writes nothing and revokes nothing.
KEEP_SCOPE = ScopeDecision()


def decide_ad_channel_scope(scope: ScopeInput) -> ScopeDecision:
    """Decide what the directory's scope-mapped groups do to one account's stored channel scope.

    **This is the one statement of the rule; other comments point here.**

    * An Administrator keeps whatever is stored; the role already reaches every channel.
    * A matching group is authoritative. Its scope replaces what is stored, an administrator's
      included, and the scope is then the directory's. A wildcard row persists the explicit
      ``["*"]`` grant; persisting NULL would now deny (BACKLOG #1152), inverting the mapping.
    * With no matching group (BACKLOG #1927), a scope an administrator set is kept, so on this
      branch the map stays opt-in. A scope that already denies is kept, because rewriting ``[]`` to
      NULL changes no decision and would revoke sessions for nothing. Any other scope is withdrawn
      to NULL, so an unvouched grant fails closed.
    """
    if scope.administrator:
        return KEEP_SCOPE
    before = scope_channels(scope.stored_scope)
    if not scope.mapped:
        if scope.stored_source == SCOPE_SOURCE_MANUAL or before == frozenset():
            return KEEP_SCOPE
        return ScopeDecision(write=True, scope_json=None, changes=True, narrows=True)
    wildcard = ALL_CHANNELS in scope.mapped
    channels = () if wildcard else tuple(sorted(scope.mapped))
    # json.dumps(sort_keys=True) is the ``_json`` the stored value has always been written with, so
    # an unchanged scope compares equal byte for byte.
    scope_json = json.dumps([ALL_CHANNELS] if wildcard else list(channels), sort_keys=True)
    if scope_json == scope.stored_scope and scope.stored_source == SCOPE_SOURCE_AD:
        return KEEP_SCOPE
    changes = scope_json != scope.stored_scope
    return ScopeDecision(
        write=True,
        scope_json=scope_json,
        changes=changes,
        narrows=changes and _narrows(before, None if wildcard else frozenset(channels)),
        wildcard=wildcard,
        channels=channels,
    )
