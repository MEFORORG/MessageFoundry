# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A directory whose answer a test sets, for the second-factor legs' directory check.

Shared by ``tests/test_mfa_directory_recheck.py`` (the TOTP leg, BACKLOG #2023) and
``tests/test_passkey_directory_recheck.py`` (the passkey leg, BACKLOG #2239), which each carried a
copy until BACKLOG #3068. All directory data a caller passes in is synthetic.

``DirectoryOf`` confirms several accounts by name. Since BACKLOG #3061 the two enrolment legs ask
the directory about a directory account too, so a test that enrols one needs a directory that
says yes.

``RebindDirectory`` answers the password re-bind step-up (``authenticate``). It moved here from
``tests/test_ad_directory_identity.py`` when ``tests/test_reauth_directory_demotion.py`` needed it
too (BACKLOG #3081).
"""

from __future__ import annotations

from messagefoundry.auth.ldap import (
    AdPrincipal,
    DirectoryAnswer,
    DirectoryBind,
    DirectoryProbe,
    LdapError,
)


class FakeDirectory:
    """Answers ``probe_principal`` as the test sets it, and records every probe.

    ``unreachable`` raises the connectivity signal. ``raises``, when set, is raised instead: a
    referral (BACKLOG #2538) or a non-LDAP fault (BACKLOG #2241)."""

    def __init__(self, principal: AdPrincipal) -> None:
        self.principal = principal
        self.answer = DirectoryAnswer.FOUND
        self.unreachable = False
        self.raises: Exception | None = None
        self.probes: list[tuple[str, str | None]] = []

    def probe_principal(self, username: str, *, object_id: str | None = None) -> DirectoryProbe:
        self.probes.append((username, object_id))
        if self.unreachable:
            raise LdapError("synthetic: LDAP socket closed")
        if self.raises is not None:
            raise self.raises
        if self.answer is DirectoryAnswer.FOUND:
            return DirectoryProbe(DirectoryAnswer.FOUND, self.principal)
        return DirectoryProbe(self.answer)


class DirectoryOf:
    """Answers ``probe_principal`` with the principal registered under the username, as present
    and enabled, and with an absent answer for any other name. Records every probe."""

    def __init__(self, *principals: AdPrincipal) -> None:
        self.principals = {p.username: p for p in principals}
        self.probes: list[tuple[str, str | None]] = []

    def probe_principal(self, username: str, *, object_id: str | None = None) -> DirectoryProbe:
        self.probes.append((username, object_id))
        principal = self.principals.get(username)
        if principal is None:
            return DirectoryProbe(DirectoryAnswer.NOT_FOUND)
        return DirectoryProbe(DirectoryAnswer.FOUND, principal)


class RebindDirectory:
    """A directory whose re-bind answer the test sets. ``bound`` is who a good password binds as;
    ``refusal`` is what the bind's own lookup found when it did not bind: ``FOUND`` for an enabled
    entry that refused the password, any other answer for no enabled entry (BACKLOG #2434).
    ``binds`` counts password binds, and ``keys`` records the ``object_id`` each call was keyed on,
    so a second directory read would show as a second key."""

    def __init__(
        self, bound: AdPrincipal | None, refusal: DirectoryAnswer | None = DirectoryAnswer.FOUND
    ) -> None:
        self.bound = bound
        self.refusal = refusal
        self.binds = 0
        self.keys: list[object] = []

    def authenticate(
        self, username: str, password: str, *, object_id: str | None = None
    ) -> DirectoryBind:
        self.binds += 1
        self.keys.append(object_id)
        if password == "synthetic-good" and self.bound is not None:
            return DirectoryBind(DirectoryAnswer.FOUND, self.bound)
        return DirectoryBind(self.refusal)

    def resolve_principal(
        self, username: str, *, object_id: str | None = None
    ) -> AdPrincipal | None:
        # The re-bind no longer reads this (BACKLOG #2434); a call would show as a second key.
        self.keys.append(object_id)
        return self.bound if self.refusal is DirectoryAnswer.FOUND else None
