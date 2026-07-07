# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Golden surface locks for the mounted /ui web console (Option B, ADR 0065).

Two drift guards over the console's externally-observable surface, both built by mounting the real
console onto a real engine app (``create_app(serve_ui=True)`` -> ``mount_ui``):

* the exact set of mounted ``(method, path)`` /ui routes matches a checked-in golden list, and
* the ``register_ui_action`` write-action patterns (``_auth._UI_WRITE_ACTIONS``) match a golden set.

A new page/route or a renamed write-action pattern is an intentional change that must update the
golden — so an *accidental* drift (a dropped route after a move, a stale/misspelled step-up pattern)
fails loudly here. A third check pins the security-relevant registration ORDER for the literal-vs-
path-param pairs (a literal route registered AFTER its ``{param}`` sibling would be shadowed — an
authz regression, e.g. ``/ui/messages/search`` swallowed by ``/ui/messages/{message_id}``).
"""

from __future__ import annotations

from pathlib import Path

import httpx
from starlette.routing import Mount

from messagefoundry.api import create_app
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

import messagefoundry_webconsole._auth as ui_auth

_GOLDEN = Path(__file__).resolve().parent / "golden"


def _read_golden(name: str) -> list[str]:
    return _GOLDEN.joinpath(name).read_text(encoding="utf-8").splitlines()


async def _serve_ui_app(engine: Engine) -> httpx.ASGITransport:
    """Build the JSON engine app with the console mounted (the create_app -> mount_ui path)."""
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    return httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))


def _mounted_ui_routes(app: object) -> list[str]:
    """Every mounted /ui route as ``"METHOD /path"`` (a StaticFiles Mount as ``"MOUNT /ui/static"``),
    deduplicated + sorted the same way the golden file is generated."""
    lines: set[str] = set()
    for route in app.router.routes:  # type: ignore[attr-defined]
        path = getattr(route, "path", None)
        if not (isinstance(path, str) and path.startswith("/ui")):
            continue
        methods = getattr(route, "methods", None)
        if methods:
            lines.update(f"{method} {path}" for method in methods)
        else:
            lines.add(f"MOUNT {path}")
    return sorted(lines)


async def test_ui_route_table_matches_golden(engine: Engine) -> None:
    """The exact mounted /ui (method, path) surface is pinned. A dropped/renamed/added route (e.g. a
    route lost in a package move, or a path-param typo) diverges from the golden and fails here."""
    transport = await _serve_ui_app(engine)
    actual = _mounted_ui_routes(transport.app)
    golden = _read_golden("ui_routes.txt")
    assert actual == golden, (
        "the mounted /ui route table drifted from tests/golden/ui_routes.txt — if intentional, "
        "regenerate the golden; if not, a route was dropped/renamed by a change.\n"
        f"missing (in golden, not mounted): {sorted(set(golden) - set(actual))}\n"
        f"unexpected (mounted, not golden): {sorted(set(actual) - set(golden))}"
    )


async def test_ui_write_action_registry_matches_golden(engine: Engine) -> None:
    """The write-action registry (``register_ui_action`` patterns) is pinned. This is the step-up
    re-auth allow-list; a stale/misspelled/renamed pattern after a route move — the exact failure a
    single-module registry can still make silently — diverges from the golden and fails here."""
    await _serve_ui_app(engine)  # mount so every module-level register_ui_action has fired
    actual = sorted(action.path_re.pattern for action in ui_auth._UI_WRITE_ACTIONS)
    golden = _read_golden("ui_write_actions.txt")
    assert actual == golden, (
        "the /ui write-action registry drifted from tests/golden/ui_write_actions.txt — if "
        "intentional, regenerate the golden; if not, a register_ui_action pattern changed.\n"
        f"missing (in golden, not registered): {sorted(set(golden) - set(actual))}\n"
        f"unexpected (registered, not golden): {sorted(set(actual) - set(golden))}"
    )


# The literal path that MUST be registered before its {param} sibling (else the path-param route
# shadows it and steals the request — a route-order authz/behaviour regression the golden set-compare
# cannot catch on its own). Verified against the pre-extraction order.
_LITERAL_BEFORE_PARAM = (
    ("/ui/messages/search", "/ui/messages/{message_id}"),
    ("/ui/connections/purge-confirm", "/ui/connections/{name}/purge/{scope}"),
    ("/ui/users/new", "/ui/users/{user_id}"),
    ("/ui/roles/new", "/ui/roles/{role_id}/edit"),
    ("/ui/dead-letters/replay-all", "/ui/dead-letters/{channel_id}/replay"),
)


async def test_literal_routes_precede_path_param_siblings(engine: Engine) -> None:
    """FastAPI/Starlette matches routes in registration order, so a literal segment must be mounted
    BEFORE the ``{param}`` route that would otherwise capture it — the route-order guard mount_ui's
    fixed registrar tuple exists to preserve."""
    transport = await _serve_ui_app(engine)
    order = [
        getattr(r, "path", None)
        for r in transport.app.router.routes  # type: ignore[attr-defined]
        if not isinstance(r, Mount)
    ]
    for literal, param in _LITERAL_BEFORE_PARAM:
        assert literal in order, f"expected literal route {literal!r} to be mounted"
        assert param in order, f"expected path-param route {param!r} to be mounted"
        assert order.index(literal) < order.index(param), (
            f"{literal!r} must register before {param!r} or the path-param route shadows it "
            "(route-order authz regression)"
        )
