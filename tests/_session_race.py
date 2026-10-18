# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Drive a session rotation into the gap between a caller's read of a session and its revoke.

Shared by the rotation-race tests (BACKLOG #2146, #3029), so the re-entrancy guard lives once.
"""

from __future__ import annotations

import pytest

from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token


def rotate_after_first_call(
    monkeypatch: pytest.MonkeyPatch,
    store: object,
    service: AuthService,
    token: str,
    names: tuple[str, ...] = ("get_session", "supersede_session"),
) -> list[str | None]:
    """Rotate ``token``'s session right after the FIRST call to one of the store's ``names`` that
    passes its hash, whichever call that is, so a test measures the gap rather than one method.

    Returns a list that stays empty until the injection fires, then holds the rotated token, or
    ``None`` if the rotation failed closed. A test asserts it is non-empty, or it measured nothing.
    """
    token_hash = hash_token(token)
    rotations: list[str | None] = []

    def _inject(name: str) -> None:
        real = getattr(store, name)

        async def _then_rotate(*args: object, **kwargs: object) -> object:
            result = await real(*args, **kwargs)
            if args and args[0] == token_hash and not rotations:
                rotations.append(None)  # claim the one injection before the rotation re-enters
                rotations[0] = await service._rotate_session_token(token)
            return result

        monkeypatch.setattr(store, name, _then_rotate)

    for name in names:
        _inject(name)
    return rotations
