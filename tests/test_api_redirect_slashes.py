# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A trailing-slash miss never redirects to an absolute http:// URL (BACKLOG #1968).

Starlette's default ``redirect_slashes=True`` answers ``GET /health/`` with a pre-auth 307 whose
absolute ``Location`` carries the request's scope scheme. Behind a TLS-terminating proxy whose
``X-Forwarded-Proto`` is not trusted, that scheme is ``http``, so the redirect would send the client
to an ``http://`` URL. ``create_app`` turns the redirect off, so a miss is a plain 404.

The positive control builds a bare FastAPI app with the default, and shows the same probe DOES see a
307 to ``http://`` there. Without it, a probe that could never observe a redirect would pass too.
"""

from __future__ import annotations

import warnings

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from messagefoundry.api import create_app

# Paths whose non-slash form is a real route, so Starlette's default would redirect the slash form.
_SLASH_PATHS = ("/health/", "/messages/", "/status/")


def _client(app: FastAPI) -> TestClient:
    # The starlette-httpx TestClient deprecation warning is noise here; silence it locally.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return TestClient(app, base_url="http://testserver", follow_redirects=False)


def _assert_no_http_redirect(app: FastAPI, path: str) -> None:
    with _client(app) as c:
        response = c.get(path)
    location = response.headers.get("location", "")
    assert response.status_code != 307, (path, response.status_code, location)
    assert not location.startswith("http://"), (path, location)


def test_create_app_turns_slash_redirects_off() -> None:
    # Pinned on the router itself, so a later constructor edit that re-enables it fails here.
    assert create_app().router.redirect_slashes is False


@pytest.mark.parametrize("path", _SLASH_PATHS)
def test_trailing_slash_miss_is_not_an_http_redirect(path: str) -> None:
    _assert_no_http_redirect(create_app(), path)


def test_the_console_app_does_not_redirect_a_trailing_slash_either() -> None:
    # mount_ui adds its routes to the same app, so the one flag covers /ui too.
    app = create_app(serve_ui=True)
    assert app.router.redirect_slashes is False
    for path in ("/ui/", "/ui/login/", *_SLASH_PATHS):
        _assert_no_http_redirect(app, path)


def test_the_non_slash_path_still_answers() -> None:
    # Control: turning the redirect off must not break the real route.
    with _client(create_app()) as c:
        assert c.get("/health").status_code == 200


def test_the_probe_sees_the_redirect_when_it_is_on() -> None:
    # Positive control: Starlette's default does emit the downgrade this module guards against.
    bare = FastAPI()

    @bare.get("/health")
    def _health() -> dict[str, str]:
        return {"status": "ok"}

    assert bare.router.redirect_slashes is True
    with _client(bare) as c:
        response = c.get("/health/")
    assert response.status_code == 307
    assert response.headers["location"].startswith("http://")
