# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Option B (ADR 0065): the engine imports, boots, and serves the JSON API with the web console (the
``messagefoundry_webconsole`` package) ABSENT, while ``serve_ui`` still fails LOUD at construction with
a clear ``RuntimeError``.

Guards the couplings that were severed so the console could move to an optional package: (1) neither
``app.py`` nor ``auth_routes.py`` carries a module-scope console reference — ``app.py`` imports
``messagefoundry_webconsole`` only inside its guarded ``serve_ui`` branch, and ``auth_routes.py``
returns an engine-side ``AdminHandlers`` bundle (leaf type in ``api._ui_seam``) and imports the console
not at all; (2) the ``/ui`` CSP is the ``app.state.ui_csp`` hook; (3) the ``/ws/stats`` browser
augmentation is the ``app.state.ui_ws_authorize`` / ``app.state.ui_connections_render`` hooks.

ADR 0143 made the console ON BY DEFAULT, so the console-absent premise changed: at the ``create_app``
level a ``serve_ui=True`` caller is being EXPLICIT and still fails LOUD (``RuntimeError``); at the
``serve`` (``__main__``) level the default-on posture SOFT-DEGRADES to a JSON-only serve + a warning
when the wheel is absent, while an EXPLICIT ``[security].serve_web_console=true`` keeps the hard
refuse (exit 2)."""

from __future__ import annotations

import builtins
import subprocess
import sys
import textwrap
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

import messagefoundry.api.app as app_module
import messagefoundry.api.auth_routes as auth_routes_module
from messagefoundry.__main__ import main
from messagefoundry.api import create_app
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"

# The stable substring of the clear startup error raised when serve_ui is on but the console is absent.
_CLEAR_ERROR = "serve_ui requires the web console"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "absent.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    return service


def _block_webui_import() -> Callable[..., Any]:
    """A ``builtins.__import__`` replacement that makes importing the web console raise ``ImportError``
    — simulating the optional package being absent. ``from messagefoundry_webconsole import mount_ui``
    compiles to ``__import__('messagefoundry_webconsole', fromlist=('mount_ui',))``, so intercept any
    ``messagefoundry_webconsole`` import; everything else passes through unchanged."""
    real_import = builtins.__import__

    def fake_import(
        name: str,
        globals: Any = None,
        locals: Any = None,
        fromlist: Any = (),
        level: int = 0,
    ) -> Any:
        if name == "messagefoundry_webconsole" or name.startswith("messagefoundry_webconsole."):
            raise ImportError("simulated: messagefoundry_webconsole is absent")
        return real_import(name, globals, locals, fromlist, level)

    return fake_import


def test_no_module_level_webui_reference() -> None:
    """``app.py`` and ``auth_routes.py`` must carry ZERO module-scope reference to the console — that is
    the structural guarantee that importing them never touches the optional package. ``app.py``'s
    reference lives only inside its guarded ``serve_ui`` branch; ``auth_routes.py`` has none."""
    assert not hasattr(app_module, "webui")
    assert not hasattr(app_module, "mount_ui")
    assert not hasattr(auth_routes_module, "webui")
    assert not hasattr(auth_routes_module, "mount_ui")


async def test_serve_ui_off_builds_json_app_with_webui_absent(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the console absent, ``create_app(serve_ui=False)`` builds a working JSON app that never
    imports ``webui``: the JSON API answers, no ``/ui`` is mounted, and — the severed CSP coupling —
    the security-headers middleware applies NO ``/ui`` Content-Security-Policy (the hook is unset)."""
    service = await _service(engine)
    monkeypatch.setattr(builtins, "__import__", _block_webui_import())

    app = create_app(engine, auth=service, serve_ui=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        assert (await c.get("/health")).status_code == 200  # the JSON API is unaffected
        r = await c.get("/ui/login")
        assert r.status_code == 404  # no /ui served
        # CSP hook absent → no /ui CSP header (JSON-only serves no HTML), but Cache-Control still set.
        header_names = {k.lower() for k in r.headers}
        assert "content-security-policy" not in header_names
        assert r.headers.get("cache-control") == "no-store"


async def test_serve_ui_on_raises_clear_error_when_webui_absent(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the console absent, ``create_app(serve_ui=True)`` fails LOUD at construction with a clear
    ``RuntimeError`` (never a bare ``ImportError`` nor a mid-request 500) from the guarded ``mount_ui``
    import in the ``serve_ui`` tail — before any ``/ui`` route or deps bundle is built."""
    service = await _service(engine)
    monkeypatch.setattr(builtins, "__import__", _block_webui_import())

    with pytest.raises(RuntimeError, match=_CLEAR_ERROR):
        create_app(engine, auth=service, serve_ui=True)


def test_engine_imports_and_boots_in_fresh_interpreter_without_webui() -> None:
    """The strongest proof: in a FRESH interpreter where ``messagefoundry_webconsole`` is unimportable
    from the very start, ``import messagefoundry.api.app`` / ``.auth_routes`` still succeed, a
    JSON-only app builds, and ``serve_ui=True`` raises the clear ``RuntimeError``. Running it in a
    subprocess guarantees the console module was NEVER imported (which the in-process tests cannot,
    since another test may already have imported it into ``sys.modules``)."""
    program = textwrap.dedent(
        f"""
        import sys

        # Make the optional console package unimportable before anything imports the engine API.
        sys.modules["messagefoundry_webconsole"] = None

        # (1) The engine API imports cleanly with the console absent (no module-scope console coupling).
        import messagefoundry.api.app as app_module
        import messagefoundry.api.auth_routes as auth_routes_module
        from messagefoundry.api import create_app

        assert not hasattr(app_module, "webui"), "app.py leaked a module-scope webui reference"
        assert not hasattr(app_module, "mount_ui"), "app.py leaked a module-scope mount_ui reference"
        assert not hasattr(
            auth_routes_module, "webui"
        ), "auth_routes.py leaked a module-scope webui reference"

        # (2) A JSON-only app builds and mounts no /ui.
        app = create_app(serve_ui=False, allow_no_auth=True)
        paths = {{getattr(r, "path", "") for r in app.routes}}
        assert "/health" in paths, "JSON API route missing"
        assert not any(p.startswith("/ui") for p in paths), "unexpected /ui route with serve_ui off"

        # (3) serve_ui=True fails LOUD with the clear RuntimeError, not a bare ImportError.
        try:
            create_app(serve_ui=True, allow_no_auth=True)
        except RuntimeError as exc:
            assert {_CLEAR_ERROR!r} in str(exc), f"unexpected message: {{exc}}"
        else:
            raise AssertionError("serve_ui=True must raise RuntimeError when the console is absent")

        print("OK")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    assert "OK" in result.stdout


# --- ADR 0143 soft-degrade contract: default-on vs explicit when the wheel is absent --------------


def _serve_with_console_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    toml: str,
) -> tuple[int, str]:
    """Run ``serve`` with ``importlib.util.find_spec`` reporting the console wheel ABSENT (the path the
    ``__main__`` gate actually probes — ``find_spec`` does not import, so the __import__ shim above does
    not cover it), the app + uvicorn mocked so no socket opens. Returns ``(exit_code, stderr)``."""
    import importlib.util as ilu

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    # GIVEN 1 (ADR 0148): dev derives PHI now, so declare synthetic to keep the PHI gates quiet — these
    # tests probe the ADR 0143 console soft-degrade / hard-refuse contract, not the security posture.
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = false\n" + toml, encoding="utf-8"
    )
    real_find_spec = ilu.find_spec

    def fake_find_spec(name: str, *a: Any, **k: Any) -> Any:
        if name == "messagefoundry_webconsole":
            return None  # simulate the optional wheel being absent
        return real_find_spec(name, *a, **k)

    monkeypatch.setattr(ilu, "find_spec", fake_find_spec)
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    rc = main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"])
    return rc, capsys.readouterr().err


def test_serve_default_on_soft_degrades_to_json_only_when_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """ADR 0143 contract (a): the console is ON BY DEFAULT, so a bare serve whose optional wheel is
    absent SOFT-DEGRADES to a JSON-only serve with a WARNING (exit 0) — it must not refuse every serve."""
    rc, err = _serve_with_console_absent(tmp_path, monkeypatch, capsys, "")
    assert rc == 0
    assert "web console is on by default" in err and "serving the JSON API only" in err


def test_serve_explicit_console_refuses_when_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """ADR 0143 contract (b): an EXPLICIT ``[security].serve_web_console=true`` with the wheel absent
    keeps the HARD refuse (exit 2) — the operator asked for the console by name."""
    rc, err = _serve_with_console_absent(
        tmp_path, monkeypatch, capsys, "security.serve_web_console = true\n"
    )
    assert rc == 2
    assert "serve_web_console=true needs the web console package" in err
