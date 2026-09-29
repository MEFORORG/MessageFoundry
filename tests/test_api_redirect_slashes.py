# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A trailing-slash miss never redirects to an absolute http:// URL (BACKLOG #1968).

Starlette's default ``redirect_slashes=True`` answers ``GET /health/`` with a pre-auth 307 whose
absolute ``Location`` carries the request's scope scheme. Behind a TLS-terminating proxy whose
``X-Forwarded-Proto`` is not trusted, that scheme is ``http``, so the redirect would send the client
to an ``http://`` URL. ``create_app`` turns the redirect off, so a miss is a plain 404.

The positive control turns the flag back on for a ``create_app`` instance and shows the same probe
DOES see a 307 to ``http://`` there. Without it, a probe that could never observe a redirect would
pass too.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from starlette.routing import Mount
from starlette.staticfiles import StaticFiles
from starlette.testclient import TestClient

from messagefoundry.api import create_app

# Paths whose non-slash form is a real route, so Starlette's default would redirect the slash form.
_API_SLASH_PATHS = ("/health/", "/messages/", "/status/")
_UI_SLASH_PATHS = ("/ui/", "/ui/login/")


def _client(app: FastAPI) -> TestClient:
    return TestClient(app, base_url="http://testserver", follow_redirects=False)


def _assert_plain_404(app: FastAPI, path: str) -> None:
    with _client(app) as c:
        response = c.get(path)
    location = response.headers.get("location", "")
    assert not location.startswith("http://"), (path, location)
    assert response.status_code == 404, (path, response.status_code, location)


def test_create_app_turns_slash_redirects_off() -> None:
    # Pinned on the router itself, so a later constructor edit that re-enables it fails here.
    assert create_app().router.redirect_slashes is False


@pytest.mark.parametrize("path", _API_SLASH_PATHS)
def test_trailing_slash_miss_is_a_plain_404(path: str) -> None:
    _assert_plain_404(create_app(), path)


def test_the_console_app_does_not_redirect_a_trailing_slash_either() -> None:
    # mount_ui adds its routes to the same app, so the one flag covers /ui too.
    app = create_app(serve_ui=True)
    assert app.router.redirect_slashes is False
    for path in (*_UI_SLASH_PATHS, *_API_SLASH_PATHS):
        _assert_plain_404(app, path)


def test_no_route_ends_in_a_slash_and_no_mount_redirects() -> None:
    # The flag makes "/x/" stop answering at "/x", and it does not reach a mounted sub-app, whose own
    # router redirects by default. Either would reopen the gap the flag closes, so pin both here.
    app = create_app(serve_ui=True)
    slash_routes = [
        path
        for route in app.routes
        if (path := getattr(route, "path", "")) != "/" and path.endswith("/")
    ]
    assert slash_routes == []
    for route in app.routes:
        if not isinstance(route, Mount):
            continue
        sub = route.app
        assert getattr(sub, "redirect_slashes", False) is False, route.path
        assert getattr(getattr(sub, "router", None), "redirect_slashes", False) is False, route.path
        # StaticFiles(html=True) redirects a directory to its slash form, the same downgrade.
        if isinstance(sub, StaticFiles):
            assert sub.html is False, route.path


def test_the_non_slash_path_still_answers() -> None:
    # Control: turning the redirect off must not break the real route.
    with _client(create_app()) as c:
        assert c.get("/health").status_code == 200


@pytest.mark.parametrize("serve_ui", [False, True])
def test_the_probe_sees_the_redirect_when_it_is_on(serve_ui: bool) -> None:
    # Positive control on the real app and its middleware stack: with Starlette's default restored,
    # the same probe sees the downgrade this module guards against.
    app = create_app(serve_ui=serve_ui)
    app.router.redirect_slashes = True
    paths = (*_API_SLASH_PATHS, *(_UI_SLASH_PATHS if serve_ui else ()))
    with _client(app) as c:
        for path in paths:
            response = c.get(path)
            assert response.status_code == 307, (path, response.status_code)
            assert response.headers["location"].startswith("http://"), path
