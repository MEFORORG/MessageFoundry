# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""FastAPI ``RouteContext`` shapes the route walk and the refusal count must both survive.

Shared by ``tests/test_route_gates.py`` and ``tests/test_route_deny_default.py``, so the one
assumption about what FastAPI changed is written once."""

from __future__ import annotations

from typing import Any

import fastapi.routing
import pytest


def route_context_forwarding_to_the_copy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``RouteContext``'s attribute fallback refuse ``starlette_route``, as FastAPI 0.143.1 and
    later do for an included non-API route: there the fallback answers from the rebuilt copy, which
    has no such field. It simulates that one read only. FastAPI 0.143.1 also moved the documented
    properties, such as ``path``, onto the copy, and this does not."""
    original = fastapi.routing.RouteContext.__getattr__

    def patched(self: Any, attr: str) -> Any:
        if attr == "starlette_route":
            raise AttributeError(attr)
        return original(self, attr)

    monkeypatch.setattr(fastapi.routing.RouteContext, "__getattr__", patched)
