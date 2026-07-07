# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Engine-side THIN mount/smoke test for the web console (Option B, ADR 0065).

The exhaustive /ui behaviour suite lives in the console's OWN package suite
(``packaging/messagefoundry-webconsole/tests/``); the engine keeps only this smoke test proving the
seam still wires up: with the ``messagefoundry_webconsole`` package installed,
``create_app(serve_ui=True)`` mounts the /ui surface (a representative set of routes + the static
mount answer), and the write-action registry the step-up re-auth flow reads is populated. The
package-ABSENT proof stays in ``tests/test_webconsole_absent.py``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

# A few representative routes from across the console's areas — enough to prove mount_ui registered
# each registrar block, without duplicating the package suite's exhaustive golden route table.
_REPRESENTATIVE_ROUTES = (
    "/ui",
    "/ui/login",
    "/ui/messages",
    "/ui/messages/search",
    "/ui/connections",
    "/ui/dead-letters",
    "/ui/status",
    "/ui/users",
    "/ui/audit",
)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "mount.db", poll_interval=0.05)
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    return service


async def test_serve_ui_mounts_login_and_static(engine: Engine) -> None:
    """The console mounts: /ui/login renders and the package's own static assets serve."""
    service = await _service(engine)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        login = await c.get("/ui/login")
        assert login.status_code == 200
        assert "text/html" in login.headers["content-type"]
        assert (await c.get("/ui/static/app.css")).status_code == 200
        assert (await c.get("/ui/static/app.js")).status_code == 200


async def test_serve_ui_registers_representative_routes(engine: Engine) -> None:
    """mount_ui registered every registrar block — proven by a representative route from each area
    being present on the app router."""
    service = await _service(engine)
    app = create_app(engine, auth=service, serve_ui=True)
    paths = {getattr(r, "path", "") for r in app.router.routes}
    missing = [p for p in _REPRESENTATIVE_ROUTES if p not in paths]
    assert not missing, (
        f"serve_ui mounted but these representative /ui routes are missing: {missing}"
    )


async def test_serve_ui_populates_write_action_registry(engine: Engine) -> None:
    """The step-up re-auth allow-list (``_UI_WRITE_ACTIONS``) is populated once the console is
    mounted — the registry the /ui/reauth flow reads to decide which actions it may continue."""
    import messagefoundry_webconsole as webconsole
    from messagefoundry_webconsole._auth import _UI_WRITE_ACTIONS

    service = await _service(engine)
    create_app(engine, auth=service, serve_ui=True)  # mount fires every register_ui_action
    assert _UI_WRITE_ACTIONS, "the /ui write-action registry is empty after mount"
    # A representative body-less step-up POST is registered as auto-retryable (the replay path).
    assert webconsole.is_safe_ui_action("/ui/messages/abc123/replay") is True
    # A registered unlock GET form page (the confirm-after-step-up primitive).
    assert webconsole.is_unlock_action("/ui/users/new") is True
