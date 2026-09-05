# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Golden surface locks for the mounted /ui web console (Option B, ADR 0065).

Two drift guards over the console's externally-observable surface, both built by mounting the real
console onto a real engine app (``create_app(serve_ui=True)`` -> ``mount_ui``):

* the exact set of mounted ``(method, path)`` /ui routes matches a checked-in golden list, and
* the ``register_ui_action`` write-action registry (``_auth._UI_WRITE_ACTIONS``) matches a golden set
  of ``pattern<TAB>action`` rows — the pattern AND the single-use step-up action tag bound to it.

A new page/route, a renamed write-action pattern, or a changed action tag is an intentional change
that must update the golden — so an *accidental* drift (a dropped route after a move, a
stale/misspelled step-up pattern, a silently deleted action tag) fails loudly here. A third check
pins the security-relevant registration ORDER for the literal-vs-path-param pairs (a literal route
registered AFTER its ``{param}`` sibling would be shadowed — an authz regression, e.g.
``/ui/messages/search`` swallowed by ``/ui/messages/{message_id}``).
"""

from __future__ import annotations

from pathlib import Path

import httpx
from starlette.routing import Mount

import messagefoundry_webconsole._auth as ui_auth
from messagefoundry.api import create_app
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

_GOLDEN = Path(__file__).resolve().parent / "golden"

# The action column's stand-in for ``UiWriteAction.action is None``. A literal marker, never an empty
# field: a blank second column is indistinguishable from a row that lost its tab, so the one drift
# this column exists to catch would read as a formatting nit.
_UNTAGGED = "-"


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
    """The write-action registry is pinned as ``pattern<TAB>action``. This is the step-up re-auth
    allow-list; a stale/misspelled/renamed pattern after a route move — the exact failure a
    single-module registry can still make silently — diverges from the golden and fails here.

    THE ACTION COLUMN IS THE SECURITY-LOAD-BEARING HALF (BACKLOG #1148). ``action`` is the
    single-use step-up grant ``/ui/reauth`` mints for a continuation (``routes/core.py`` passes it
    as ``purpose``); ``None`` mints nothing, so the lane falls back to the shared login-seeded
    window. Deleting one ``action=`` kwarg therefore downgrades a factor-binding browser lane from a
    fresh per-action proof to a window a five-minute-old login satisfies, in a one-line deletion
    that reads like tidying.

    WHAT WAS ACTUALLY MEASURED, because the honest result is narrower than "it was unguarded".
    A mutation sweep deleted each of the 9 ``action=`` kwargs in turn:

    * this golden caught NONE of them. It compared ``path_re.pattern`` only, so the field that
      changed was invisible to it while its own docstring called it the step-up allow-list guard.
    * behavioural console tests caught all 9, but incidentally: they were written for the MFA,
      WebAuthn and session lifecycles, and they report "the lifecycle broke", not "this pattern lost
      its action tag".
    * for the 2 WebAuthn lanes that coverage exists ONLY with the optional ``[webauthn]`` extra
      installed. Without it those tests ``importorskip`` and both deletions ran completely GREEN —
      so a contributor without the extra gets a clean local run on a real downgrade.

    So this column does not close an unguarded hole. It replaces incidental, extra-gated coverage
    with a direct one that names the field. Pin the pair, not the pattern.
    """
    await _serve_ui_app(engine)  # mount so every module-level register_ui_action has fired
    actual = sorted(
        f"{action.path_re.pattern}\t{action.action or _UNTAGGED}"
        for action in ui_auth._UI_WRITE_ACTIONS
    )
    golden = _read_golden("ui_write_actions.txt")
    assert actual == golden, (
        "the /ui write-action registry drifted from tests/golden/ui_write_actions.txt — if "
        "intentional, regenerate the golden; if not, a register_ui_action pattern or its step-up "
        "action tag changed. A row whose action column went to "
        f"{_UNTAGGED!r} LOST its single-use grant and now rides the shared step-up window.\n"
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
