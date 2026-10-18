# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A directory whose answer a test sets, for the second-factor legs' directory check.

Shared by ``tests/test_mfa_directory_recheck.py`` (the TOTP leg, BACKLOG #2023) and
``tests/test_passkey_directory_recheck.py`` (the passkey leg, BACKLOG #2239), which each carried a
copy until BACKLOG #3068. All directory data a caller passes in is synthetic.
"""

from __future__ import annotations

from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer, DirectoryProbe, LdapError


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
