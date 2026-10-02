# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Lift ONLY the custom-role pairing rule, for tests that pin the route-level second line.

Minting refuses a custom role holding ``messages:view_raw`` without ``messages:view_summary``, and
decoding drops ``view_raw`` from a stored one (vault BACKLOG #1187). Both decisions go through one
predicate, :func:`messagefoundry.auth.permissions.raw_body_without_summary`, so patching it to answer
``False`` lifts exactly that rule: the validator's other rules (unknown names, an empty set, the
forbidden escalation permissions) and the decoder's defences all still run. No route gate calls the
predicate, so the routes' own checks stay live, which is what these tests exist to prove. This module is
the one place that states the bypass; the tests using it point here. Test-only.
"""

from __future__ import annotations

import pytest

from messagefoundry.auth import permissions


def bypass_view_raw_pairing_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let a custom role hold ``messages:view_raw`` without ``messages:view_summary``."""
    monkeypatch.setattr(permissions, "raw_body_without_summary", lambda _perms: False)
