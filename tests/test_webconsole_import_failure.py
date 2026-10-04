# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1907: a web console that is INSTALLED but fails to import gets a named refusal.

An old console (the filing measured 0.2.15 against engine 0.4.0) lacks names this engine imports, so
the import raises ``ImportError`` before ``assert_engine_seam`` can raise ``UiSeamMismatch``. On
``serve`` that reached the CLI's last-resort catch (exit 1, one generic log line); in ``create_app``
it was reported as "not installed".

The filing's reproduction needs a real 0.2.15 wheel in a second environment. These tests stand a
FAKE ``messagefoundry_webconsole`` package on ``sys.path`` instead, whose ``__init__`` fails with a
genuine ``cannot import name`` error from an engine module, which is the shape an old or skewed
console produces. The real import machinery runs, so this is closer to the defect than shadowing
``builtins.__import__``.
"""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

import messagefoundry.__main__ as main_module
from messagefoundry.__main__ import main
from messagefoundry.api import create_app
from messagefoundry.api._ui_seam import ENGINE_UI_SEAM
from messagefoundry.api._webconsole_import import (
    WEBCONSOLE_IMPORT_NAME,
    console_import_failure,
    console_is_absent,
)
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"

# A name the engine seam module does not define. Importing it raises the same "cannot import name"
# ImportError an old console raises when it reaches for an engine name that moved or never existed.
_MISSING = "NameThisEngineDoesNotDefine1907"


def _install_broken_console(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Put a fake console first on ``sys.path`` whose import fails, and evict the real one.

    ``monkeypatch`` restores every evicted ``sys.modules`` entry and ``sys.path`` afterwards, so the
    real console is back for the next test."""
    pkg = tmp_path / "fake_console" / WEBCONSOLE_IMPORT_NAME
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(
        f"from messagefoundry.api._ui_seam import {_MISSING}  # noqa: F401\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(pkg.parent))
    for name in [
        m
        for m in sys.modules
        if m == WEBCONSOLE_IMPORT_NAME or m.startswith(WEBCONSOLE_IMPORT_NAME + ".")
    ]:
        monkeypatch.delitem(sys.modules, name)


def test_absence_is_only_the_package_itself_missing() -> None:
    """Only ``ModuleNotFoundError`` naming the console's own package means "not installed"."""
    assert console_is_absent(ModuleNotFoundError("gone", name=WEBCONSOLE_IMPORT_NAME))
    # A missing submodule or dependency means the console IS installed and broke on the way in.
    assert not console_is_absent(
        ModuleNotFoundError("gone", name=f"{WEBCONSOLE_IMPORT_NAME}.pages")
    )
    assert not console_is_absent(ModuleNotFoundError("gone", name="some_dependency"))
    assert not console_is_absent(ImportError(f"cannot import name {_MISSING!r}"))


def test_message_names_the_seam_and_the_installed_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """It names what the engine holds, the seam, and the installed version. It invents no
    "required console version", because the engine has none."""
    monkeypatch.setattr("importlib.metadata.version", lambda dist: "0.2.15")
    msg = console_import_failure(ImportError(f"cannot import name {_MISSING!r}"))
    assert ENGINE_UI_SEAM in msg
    assert "reports version 0.2.15" in msg
    assert "failed to import" in msg
    assert _MISSING in msg
    assert "not installed" not in msg
    assert "required" not in msg


def test_message_survives_missing_distribution_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib.metadata

    def no_metadata(dist: str) -> str:
        raise importlib.metadata.PackageNotFoundError(dist)

    monkeypatch.setattr("importlib.metadata.version", no_metadata)
    msg = console_import_failure(ImportError("boom"))
    assert "no distribution metadata names its version" in msg
    assert ENGINE_UI_SEAM in msg


def test_a_missing_third_party_dependency_is_named_rather_than_blamed_on_skew() -> None:
    """A console missing a dependency needs that dependency, not another console release."""
    msg = console_import_failure(ModuleNotFoundError("No module named 'jinja2'", name="jinja2"))
    assert "needs the module 'jinja2'" in msg
    assert "older or newer" not in msg
    # A missing engine submodule IS skew, so it keeps the seam advice.
    skew = console_import_failure(
        ModuleNotFoundError("gone", name="messagefoundry.api._gone_module")
    )
    assert ENGINE_UI_SEAM in skew and "older or newer" in skew


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "broken.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def test_create_app_names_a_broken_console_rather_than_calling_it_absent(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    _install_broken_console(tmp_path, monkeypatch)

    with pytest.raises(RuntimeError, match="serve_ui requires the web console") as info:
        create_app(engine, auth=service, serve_ui=True)
    msg = str(info.value)
    assert "not installed" not in msg, msg
    assert "failed to import" in msg, msg
    assert ENGINE_UI_SEAM in msg, msg
    assert _MISSING in msg, msg
    assert isinstance(info.value.__cause__, ImportError)


def test_serve_refuses_a_broken_console_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``serve`` exits 2 with a named refusal. Before the fix it exited 1 through the last-resort
    catch, so ``rc == 2`` and the refusal line are what tell the two apart.

    The provenance gate runs first and would refuse the fake package on its own, since no installed
    distribution owns it. Its documented opt-out lets the import go ahead, which also shows the new
    refusal sits AFTER the provenance measurement."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    monkeypatch.setenv(main_module.WEBCONSOLE_PROVENANCE_OPT_OUT, "1")
    (tmp_path / "messagefoundry.toml").write_text(
        "security.block_unlisted_outbound = true\n"
        "security.allow_unencrypted_phi = true\n"
        "security.allow_unencrypted_phi_under_strict_enforcement = true\n"
        "alerts.security_notifications_required = false\n",
        encoding="utf-8",
    )
    built: list[object] = []
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: built.append(kw))
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    _install_broken_console(tmp_path, monkeypatch)

    rc = main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"])
    err = capsys.readouterr().err

    assert rc == 2, err
    assert "provenance is UNVERIFIED" in err, "the provenance gate did not run first"
    assert "error: refusing to mount the web console:" in err, err
    assert "failed to import" in err and ENGINE_UI_SEAM in err and _MISSING in err, err
    assert not built, "serve reached create_managed_app past a console that would not import"


pytestmark = pytest.mark.usefixtures("bounded_warn_only_retention", "verified_log_forwarding")
