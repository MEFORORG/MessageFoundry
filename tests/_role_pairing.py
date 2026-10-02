# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Lift ONLY the custom-role pairing rule, for tests that pin the route-level second line.

Minting refuses a custom role holding ``messages:view_raw`` without ``messages:view_summary``, and
decoding drops ``view_raw`` from a stored one (vault BACKLOG #1187). A test that proves the ROUTES still
withhold what such an identity must not see has to build one anyway. These stand-ins wrap the real
validator and decoder, so every other rule (unknown names, an empty set, the forbidden escalation
permissions) still applies; only the pairing rule is lifted. Test-only: nothing in the engine reaches it.
"""

from __future__ import annotations

import json

import pytest

from messagefoundry.auth import permissions as real
from messagefoundry.auth.permissions import Permission


def bypass_view_raw_pairing_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch the service's validator and decoder so a ``view_raw``-only custom role can exist."""
    import messagefoundry.auth.service as service_module

    def validate(values: list[str]) -> list[Permission]:
        asked = set(values)
        perms = real.validate_custom_role_permissions(
            [*values, Permission.MESSAGES_VIEW_SUMMARY.value]
        )
        if Permission.MESSAGES_VIEW_SUMMARY.value not in asked:
            perms = [p for p in perms if p is not Permission.MESSAGES_VIEW_SUMMARY]
        return perms

    def decode(raw: str | None) -> frozenset[Permission]:
        perms = real.decode_custom_role_permissions(raw)
        try:
            stored = json.loads(raw or "[]")
        except ValueError:
            return perms
        if isinstance(stored, list) and Permission.MESSAGES_VIEW_RAW.value in stored:
            perms |= {Permission.MESSAGES_VIEW_RAW}
        return perms

    monkeypatch.setattr(service_module, "validate_custom_role_permissions", validate)
    monkeypatch.setattr(service_module, "decode_custom_role_permissions", decode)
