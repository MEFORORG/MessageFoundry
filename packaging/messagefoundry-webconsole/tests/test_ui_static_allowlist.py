# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 13.4.7 — ``/ui/static`` serves ONLY allow-listed file extensions.

A bare ``StaticFiles`` mount serves any regular file under its directory: its only containment is
path-traversal defence. That was the whole of the console's asset-tier containment, and the directory
is the live working tree under the editable dev/CI install, so a stray ``.map``, editor backup,
``x.py`` or ``.env`` would have been served UNAUTHENTICATED with a 200.

These tests drive the real mount over a throwaway directory with those exact files planted in it —
proving the refusal at the HTTP layer rather than by reading the code — plus the unit-level rule and
the still-working real assets.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from messagefoundry.api import create_app
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole._static import (
    ALLOWED_STATIC_EXTENSIONS,
    AllowlistedStaticFiles,
    static_path_allowed,
)

#: Names a packaging accident, an editor, a secret leak or a source file would drop into the asset
#: directory. Every one of these is served 200 by a bare StaticFiles mount.
PLANTED = (
    "secrets.map",  # a source map next to a minified asset
    "app.js.bak",  # an editor/backup copy of a REAL served asset
    "x.py",  # a source file
    ".env",  # the worst case: git-ignored, so invisible to review
    "app.css.map",
    ".htpasswd",
    "notes",  # no extension at all
    "connections.toml",
)


@pytest.fixture
def planted_dir(tmp_path: Path) -> Path:
    """A static directory holding one legitimately-servable asset of each allowed kind plus every
    planted file above — including one inside a SUBDIRECTORY, since the rule applies to the final
    component of the whole relative path."""
    root = tmp_path / "static"
    root.mkdir()
    (root / "app.css").write_text("body{}", encoding="utf-8")
    (root / "app.js").write_text("void 0;", encoding="utf-8")
    for name in PLANTED:
        (root / name).write_text("planted", encoding="utf-8")
    nested = root / "sub"
    nested.mkdir()
    (nested / "deep.key").write_text("planted", encoding="utf-8")
    (nested / "ok.js").write_text("void 0;", encoding="utf-8")
    return root


def _mounted(directory: Path) -> httpx.AsyncClient:
    app = FastAPI()
    app.mount("/ui/static", AllowlistedStaticFiles(directory=str(directory)), name="ui-static")
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def test_planted_files_are_404(planted_dir: Path) -> None:
    """Every planted file 404s even though it exists on disk under the served directory."""
    async with _mounted(planted_dir) as c:
        for name in PLANTED:
            r = await c.get(f"/ui/static/{name}")
            assert r.status_code == 404, f"{name} was served: {r.status_code}"
        # a disallowed extension inside a SUBDIRECTORY is refused too
        assert (await c.get("/ui/static/sub/deep.key")).status_code == 404


async def test_allowed_assets_still_serve(planted_dir: Path) -> None:
    """The allowlist must not break the console: both allowed kinds still serve, at the top level and
    nested."""
    async with _mounted(planted_dir) as c:
        assert (await c.get("/ui/static/app.css")).status_code == 200
        assert (await c.get("/ui/static/app.js")).status_code == 200
        assert (await c.get("/ui/static/sub/ok.js")).status_code == 200


async def test_traversal_is_still_refused(planted_dir: Path) -> None:
    """The base class's traversal defence is untouched by the override."""
    async with _mounted(planted_dir) as c:
        assert (await c.get("/ui/static/../conftest.py")).status_code == 404
        assert (await c.get("/ui/static/%2e%2e/conftest.py")).status_code == 404


def test_rule_rejects_each_named_class() -> None:
    assert frozenset({".css", ".js"}) == ALLOWED_STATIC_EXTENSIONS
    for allowed in ("app.css", "app.js", "sub/ok.js", "csp-probe.js", "APP.JS"):
        assert static_path_allowed(allowed), allowed
    for refused in (
        ".env",  # dotfile: no stem, so no suffix
        ".htpasswd",
        "app.js.bak",  # multi-suffix backup of a real asset
        "notes.bak.js",  # multi-suffix even when the LAST suffix is allow-listed
        "secrets.map",
        "app.css.map",
        "x.py",
        "connections.toml",
        "notes",  # extension-less
        "sub/deep.key",
        "",
    ):
        assert not static_path_allowed(refused), refused


# --- the real console mount keeps working ---------------------------------------------------------


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    return service


async def test_real_console_assets_still_serve_unauthenticated(engine: Engine) -> None:
    """The shipped assets — including the 3.7.5 canary probe, whose absence would silently kill the
    enforcement detect — still serve 200 through the real mount."""
    service = await _service(engine)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        for asset in ("app.css", "app.js", "csp-probe.js"):
            assert (await c.get(f"/ui/static/{asset}")).status_code == 200, asset
        # and a name that is NOT in the shipped manifest is refused rather than 404-by-absence-only
        assert (await c.get("/ui/static/app.js.bak")).status_code == 404
